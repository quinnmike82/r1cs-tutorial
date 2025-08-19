use crate::account::AccountInformationVar;
use crate::ledger::{self, AccPathVar, AccRootVar, AmountVar};
use crate::transaction::TransactionVar;
use crate::ConstraintF;

use ark_r1cs_std::prelude::*;
use ark_relations::r1cs::SynthesisError;

/// Wraps an existing TransactionVar and a fee amount.
pub struct TransactionWithFeeVar {
    pub inner: TransactionVar, // (sender, recipient, amount, signature)
    pub fee: AmountVar,        // fee charged to sender, paid to fee-collector
}

impl TransactionWithFeeVar {
    pub fn new(inner: TransactionVar, fee: AmountVar) -> Self {
        Self { inner, fee }
    }

    /// Validate the tx + fee against the ledger state.
    /// Checks:
    ///   - signature verifies (same as TransactionVar),
    ///   - sender balance decreases by amount + fee,
    ///   - recipient balance increases by amount,
    ///   - fee-collector balance increases by fee,
    ///   - all 3 membership proofs (pre) and 3 membership proofs (post) are correct.
    pub fn validate_with_fee(
        &self,
        parameters: &ledger::ParametersVar,
        // sender
        pre_sender_acc_info: &AccountInformationVar,
        pre_sender_path: &AccPathVar,
        post_sender_path: &AccPathVar,
        // recipient
        pre_recipient_acc_info: &AccountInformationVar,
        pre_recipient_path: &AccPathVar,
        post_recipient_path: &AccPathVar,
        // fee-collector
        pre_fee_acc_info: &AccountInformationVar,
        pre_fee_path: &AccPathVar,
        post_fee_path: &AccPathVar,
        // roots
        pre_root: &AccRootVar,
        post_root: &AccRootVar,
    ) -> Result<Boolean<ConstraintF>, SynthesisError> {
        // 1) Signature (note: this binds the original message; if you want to bind `fee`,
        //    extend the message in TransactionVar.verify_signature to include it).
        let sig_ok = self
            .inner
            .verify_signature(&parameters.sig_params, &pre_sender_acc_info.public_key)?;

        // 2) Balances after tx+fee
        // sender: −amount −fee
        let mut post_sender = pre_sender_acc_info.clone();
        let after_amt = post_sender.balance.checked_sub(&self.inner.amount)?;
        post_sender.balance = after_amt.checked_sub(&self.fee)?;

        // recipient: +amount
        let mut post_recipient = pre_recipient_acc_info.clone();
        post_recipient.balance = post_recipient.balance.checked_add(&self.inner.amount)?;

        // fee-collector: +fee
        let mut post_fee = pre_fee_acc_info.clone();
        post_fee.balance = post_fee.balance.checked_add(&self.fee)?;

        // 3) Merkle membership checks (pre)
        let sender_exists = pre_sender_path.verify_membership(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            pre_root,
            &pre_sender_acc_info.to_bytes_le().as_slice(),
        )?;
        let recipient_exists = pre_recipient_path.verify_membership(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            pre_root,
            &pre_recipient_acc_info.to_bytes_le().as_slice(),
        )?;
        let fee_exists = pre_fee_path.verify_membership(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            pre_root,
            &pre_fee_acc_info.to_bytes_le().as_slice(),
        )?;

        // 4) Merkle membership checks (post)
        let sender_updated = post_sender_path.verify_membership(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            post_root,
            &post_sender.to_bytes_le().as_slice(),
        )?;
        let recipient_updated = post_recipient_path.verify_membership(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            post_root,
            &post_recipient.to_bytes_le().as_slice(),
        )?;
        let fee_updated = post_fee_path.verify_membership(
            &parameters.leaf_crh_params,
            &parameters.two_to_one_crh_params,
            post_root,
            &post_fee.to_bytes_le().as_slice(),
        )?;

        // 5) Combine all conditions
        sender_exists
            .and(&sender_updated)?
            .and(&recipient_exists)?
            .and(&recipient_updated)?
            .and(&fee_exists)?
            .and(&fee_updated)?
            .and(&sig_ok)
    }
}
