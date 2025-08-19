pub type ConstraintF = ark_bls12_381::Fr;

pub mod account;
pub mod ledger;
pub mod transaction;
pub mod rollup;

#[cfg(test)]
mod tests {
    use crate::rollup::Rollup;
    use ark_relations::r1cs::{ConstraintLayer, ConstraintSynthesizer, ConstraintSystem, TracingMode::OnlyConstraints};
    use tracing_subscriber::layer::SubscriberExt;
    use ark_simple_payments::ledger::{Amount, Parameters, State};
    use ark_simple_payments::transaction::Transaction;

    #[test]
    fn fee_as_second_tx_validity_test() {
        // tracing (optional)
        let mut layer = ConstraintLayer::default();
        layer.mode = OnlyConstraints;
        let subscriber = tracing_subscriber::Registry::default().with(layer);
        let _guard = tracing::subscriber::set_default(subscriber);

        let mut rng = ark_std::test_rng();
        let pp = Parameters::sample(&mut rng);
        let mut state = State::new(32, &pp);

        // Accounts
        let (alice_id, _alice_pk, alice_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();
        state.update_balance(alice_id, Amount(20)).unwrap();

        let (bob_id, _bob_pk, _bob_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();
        let (collector_id, _c_pk, _c_sk) = state.sample_keys_and_register(&pp, &mut rng).unwrap();

        // tx + fee-as-tx
        let tx      = Transaction::create(&pp, alice_id, bob_id,       Amount(5), &alice_sk, &mut rng);
        let fee_tx  = Transaction::create(&pp, alice_id, collector_id, Amount(2), &alice_sk, &mut rng);

        let mut temp_state = state.clone();
        let rollup = Rollup::<2>::with_state_and_transactions(
            pp.clone(),
            &[tx.clone(), fee_tx.clone()],
            &mut temp_state,
            true,
        ).unwrap();

        // Prove constraints
        let cs = ConstraintSystem::new_ref();
        rollup.generate_constraints(cs.clone()).unwrap();
        assert!(cs.is_satisfied().unwrap());

        // Native balances reflect (5 to Bob) and (2 to collector)
        assert_eq!(temp_state.id_to_account_info.get(&alice_id).unwrap().balance, Amount(20 - 5 - 2));
        assert_eq!(temp_state.id_to_account_info.get(&bob_id).unwrap().balance,   Amount(5));
        assert_eq!(temp_state.id_to_account_info.get(&collector_id).unwrap().balance, Amount(2));
    }
}
