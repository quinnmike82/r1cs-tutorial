use crate::account::AccountInformationVar;
use crate::ledger::*;
use crate::transaction::TransactionVar;
use crate::ConstraintF;
use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_simple_payments::{
    account::AccountInformation,
    ledger::{AccPath, AccRoot, Parameters, State},
    transaction::Transaction,
};

pub struct Rollup<const NUM_TX: usize> {
    /// The ledger parameters.
    pub ledger_params: Parameters,
    /// The Merkle tree root before applying this batch of transactions.
    pub initial_root: Option<AccRoot>,
    /// The Merkle tree root after applying this batch of transactions.
    pub final_root: Option<AccRoot>,
    /// The current batch of transactions.
    pub transactions: Option<Vec<Transaction>>,
    /// The sender's account information and corresponding authentication path,
    /// *before* applying the transactions.
    pub sender_pre_tx_info_and_paths: Option<Vec<(AccountInformation, AccPath)>>,
    /// The authentication path corresponding to the sender's account information
    /// *after* applying the transactions.
    pub sender_post_paths: Option<Vec<AccPath>>,
    /// The recipient's account information and corresponding authentication path,
    /// *before* applying the transactions.
    pub recv_pre_tx_info_and_paths: Option<Vec<(AccountInformation, AccPath)>>,
    /// The authentication path corresponding to the recipient's account information
    /// *after* applying the transactions.
    pub recv_post_paths: Option<Vec<AccPath>>,
    /// List of state roots, so that the i-th root is the state roots before applying
    /// the i-th transaction. This means that `pre_tx_roots[0] == initial_root`.
    pub pre_tx_roots: Option<Vec<AccRoot>>,
    /// List of state roots, so that the i-th root is the state root after applying
    /// the i-th transaction. This means that `post_tx_roots[NUM_TX - 1] == final_root`.
    pub post_tx_roots: Option<Vec<AccRoot>>,
}

impl<const NUM_TX: usize> Rollup<NUM_TX> {
    pub fn new_empty(ledger_params: Parameters) -> Self {
        Self {
            ledger_params,
            initial_root: None,
            final_root: None,
            transactions: None,
            sender_pre_tx_info_and_paths: None,
            sender_post_paths: None,
            recv_pre_tx_info_and_paths: None,
            recv_post_paths: None,
            pre_tx_roots: None,
            post_tx_roots: None,
        }
    }

    pub fn only_initial_and_final_roots(
        ledger_params: Parameters,
        initial_root: AccRoot,
        final_root: AccRoot,
    ) -> Self {
        Self {
            ledger_params,
            initial_root: Some(initial_root),
            final_root: Some(final_root),
            transactions: None,
            sender_pre_tx_info_and_paths: None,
            sender_post_paths: None,
            recv_pre_tx_info_and_paths: None,
            recv_post_paths: None,
            pre_tx_roots: None,
            post_tx_roots: None,
        }
    }

    pub fn with_state_and_transactions(
        ledger_params: Parameters,
        transactions: &[Transaction],
        state: &mut State,
        validate_transactions: bool,
    ) -> Option<Self> {
        assert_eq!(transactions.len(), NUM_TX);
        let initial_root = Some(state.root());
        let mut sender_pre_tx_info_and_paths = Vec::with_capacity(NUM_TX);
        let mut recipient_pre_tx_info_and_paths = Vec::with_capacity(NUM_TX);
        let mut sender_post_paths = Vec::with_capacity(NUM_TX);
        let mut recipient_post_paths = Vec::with_capacity(NUM_TX);
        let mut pre_tx_roots = Vec::with_capacity(NUM_TX);
        let mut post_tx_roots = Vec::with_capacity(NUM_TX);

        for tx in transactions {
            if !tx.validate(&ledger_params, &*state) && validate_transactions {
                return None;
            }
        }

        for tx in transactions {
            let sender_id = tx.sender;
            let recipient_id = tx.recipient;
            let pre_tx_root = state.root();

            let sender_pre_acc_info = *state.id_to_account_info.get(&sender_id)?;
            let sender_pre_path = state.account_merkle_tree
                .generate_proof(sender_id.0 as usize)
                .unwrap();

            let recipient_pre_acc_info = *state.id_to_account_info.get(&recipient_id)?;
            let recipient_pre_path = state.account_merkle_tree
                .generate_proof(recipient_id.0 as usize)
                .unwrap();

            if validate_transactions {
                state.apply_transaction(&ledger_params, tx)?;
            } else {
                let _ = state.apply_transaction(&ledger_params, tx);
            }

            let post_tx_root = state.root();
            let sender_post_path = state.account_merkle_tree
                .generate_proof(sender_id.0 as usize)
                .unwrap();
            let recipient_post_path = state.account_merkle_tree
                .generate_proof(recipient_id.0 as usize)
                .unwrap();

            sender_pre_tx_info_and_paths.push((sender_pre_acc_info, sender_pre_path));
            recipient_pre_tx_info_and_paths.push((recipient_pre_acc_info, recipient_pre_path));
            sender_post_paths.push(sender_post_path);
            recipient_post_paths.push(recipient_post_path);
            pre_tx_roots.push(pre_tx_root);
            post_tx_roots.push(post_tx_root);
        }

        Some(Self {
            ledger_params,
            initial_root,
            final_root: Some(state.root()),
            transactions: Some(transactions.to_vec()),
            sender_pre_tx_info_and_paths: Some(sender_pre_tx_info_and_paths),
            recv_pre_tx_info_and_paths: Some(recipient_pre_tx_info_and_paths),
            sender_post_paths: Some(sender_post_paths),
            recv_post_paths: Some(recipient_post_paths),
            pre_tx_roots: Some(pre_tx_roots),
            post_tx_roots: Some(post_tx_roots),
        })
    }
}

impl<const NUM_TX: usize> ConstraintSynthesizer<ConstraintF> for Rollup<NUM_TX> {
    #[tracing::instrument(target = "r1cs", skip(self, cs))]
    fn generate_constraints(
        self,
        cs: ConstraintSystemRef<ConstraintF>,
    ) -> Result<(), SynthesisError> {
        // Parameters constant
        let ledger_params = ParametersVar::new_constant(
            ark_relations::ns!(cs, "Ledger parameters"),
            &self.ledger_params,
        )?;

        // Public inputs: initial and final root
        let initial_root = AccRootVar::new_input(ark_relations::ns!(cs, "Initial root"), || {
            self.initial_root.ok_or(SynthesisError::AssignmentMissing)
        })?;
        let final_root = AccRootVar::new_input(ark_relations::ns!(cs, "Final root"), || {
            self.final_root.ok_or(SynthesisError::AssignmentMissing)
        })?;

        let mut prev_root = initial_root;

        for i in 0..NUM_TX {
            let tx = self.transactions.as_ref().and_then(|t| t.get(i));
            let sender_acc_info = self.sender_pre_tx_info_and_paths.as_ref().map(|t| t[i].0);
            let sender_pre_path = self.sender_pre_tx_info_and_paths.as_ref().map(|t| &t[i].1);

            let recipient_acc_info = self.recv_pre_tx_info_and_paths.as_ref().map(|t| t[i].0);
            let recipient_pre_path = self.recv_pre_tx_info_and_paths.as_ref().map(|t| &t[i].1);

            let sender_post_path = self.sender_post_paths.as_ref().map(|t| &t[i]);
            let recipient_post_path = self.recv_post_paths.as_ref().map(|t| &t[i]);

            let pre_tx_root = self.pre_tx_roots.as_ref().map(|t| t[i]);
            let post_tx_root = self.post_tx_roots.as_ref().map(|t| t[i]);

            // Witnesses:
            let tx = TransactionVar::new_witness(ark_relations::ns!(cs, "Transaction"), || {
                tx.ok_or(SynthesisError::AssignmentMissing)
            })?;

            let sender_acc_info = AccountInformationVar::new_witness(
                ark_relations::ns!(cs, "Sender Account Info"),
                || sender_acc_info.ok_or(SynthesisError::AssignmentMissing),
            )?;

            let sender_pre_path =
                AccPathVar::new_witness(ark_relations::ns!(cs, "Sender Pre-Path"), || {
                    sender_pre_path.ok_or(SynthesisError::AssignmentMissing)
                })?;

            let sender_post_path =
                AccPathVar::new_witness(ark_relations::ns!(cs, "Sender Post-Path"), || {
                    sender_post_path.ok_or(SynthesisError::AssignmentMissing)
                })?;

            let recipient_acc_info = AccountInformationVar::new_witness(
                ark_relations::ns!(cs, "Recipient Account Info"),
                || recipient_acc_info.ok_or(SynthesisError::AssignmentMissing),
            )?;

            let recipient_pre_path =
                AccPathVar::new_witness(ark_relations::ns!(cs, "Recipient Pre-Path"), || {
                    recipient_pre_path.ok_or(SynthesisError::AssignmentMissing)
                })?;

            let recipient_post_path =
                AccPathVar::new_witness(ark_relations::ns!(cs, "Recipient Post-Path"), || {
                    recipient_post_path.ok_or(SynthesisError::AssignmentMissing)
                })?;

            let pre_tx_root =
                AccRootVar::new_witness(ark_relations::ns!(cs, "Pre-tx Root"), || {
                    pre_tx_root.ok_or(SynthesisError::AssignmentMissing)
                })?;

            let post_tx_root =
                AccRootVar::new_witness(ark_relations::ns!(cs, "Post-tx Root"), || {
                    post_tx_root.ok_or(SynthesisError::AssignmentMissing)
                })?;

            // Chain roots
            prev_root.enforce_equal(&pre_tx_root)?;

            // Validate tx
            tx.validate(
                &ledger_params,
                &sender_acc_info,
                &sender_pre_path,
                &sender_post_path,
                &recipient_acc_info,
                &recipient_pre_path,
                &recipient_post_path,
                &pre_tx_root,
                &post_tx_root,
            )?
            .enforce_equal(&Boolean::TRUE)?;

            // advance
            prev_root = post_tx_root;
        }

        // Final root must match
        prev_root.enforce_equal(&final_root)?;
        Ok(())
    }
}
