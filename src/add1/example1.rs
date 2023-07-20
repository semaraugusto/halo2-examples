use halo2_proofs::{arithmetic::Field, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

// Table setup
//
//        a    |  selector  |
// --------------------------------------------------------------------------------
//    scalar   |     1      |
//        a0   |     x      |
//        a1   |     x      |

#[derive(Clone, Debug)]
pub struct AddScalarConfig {
    pub advice: Column<Advice>,
    pub selector: Selector,
    pub instance: Column<Instance>,
}

#[derive(Clone, Debug)]
pub struct AddScalarChip<F: Field> {
    config: AddScalarConfig,
    _marker: PhantomData<F>,
}

impl<F: Field> AddScalarChip<F> {
    pub fn construct(config: AddScalarConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> AddScalarConfig {
        let instance = meta.instance_column();
        let col_a = meta.advice_column();
        let selector = meta.selector();

        meta.enable_equality(col_a);
        meta.enable_equality(instance);

        meta.create_gate("add", |meta| {
            let selector = meta.query_selector(selector);
            // let scalar = meta.query_selector(selector);
            let scalar = meta.query_advice(col_a, Rotation::cur());
            let a = meta.query_advice(col_a, Rotation::next());
            let out = meta.query_advice(col_a, Rotation(2));

            vec![selector * ((a + scalar) - out)]
        });

        AddScalarConfig {
            advice: col_a,
            selector,
            instance,
        }
    }

    pub fn assign(
        &self,
        value: F,
        scalar: F,
        nrows: usize,
        mut layouter: impl Layouter<F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "entire circuit",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                let scalar_cell = region.assign_advice(
                    || "a0",
                    self.config.advice,
                    0,
                    || Value::known(scalar),
                )?;

                let mut value_cell =
                    region.assign_advice(|| "a0", self.config.advice, 1, || Value::known(value))?;

                // println!("0 scalar: {:?}", scalar_cell.value());
                // println!("1 value: {:?}", value_cell.value());
                for row in 2..=nrows {
                    value_cell = region.assign_advice(
                        || "a0 + scalar",
                        self.config.advice,
                        row,
                        || value_cell.value().copied() + scalar_cell.value(),
                    )?;
                    // println!("{row} value: {:?}", value_cell.value());
                }

                Ok(value_cell)
            },
        )
    }
    pub fn expose_public(
        &self,
        mut layouter: impl Layouter<F>,
        cell: &AssignedCell<F, F>,
        row: usize,
    ) -> Result<(), Error> {
        layouter.constrain_instance(cell.cell(), self.config.instance, row)
    }
}

#[derive(Default, Clone, Debug)]
pub struct MyCircuit<F: Field> {
    pub scalar: F,
    pub value: F,
    pub nrows: usize,
    pub _marker: PhantomData<F>,
}
//
// PhantomData<F>);

// use pasta_curves::pallas;
// impl<F: Field> Circuit<F> for MyCircuit<F> {
// impl Circuit<pallas::Base> for MyCircuit<pallas::Base> {

impl<F: Field> Circuit<F> for MyCircuit<F> {
    type Config = AddScalarConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        AddScalarChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = AddScalarChip::<F>::construct(config);

        let out = chip.assign(
            self.value,
            self.scalar,
            self.nrows,
            layouter.namespace(|| "initial values"),
        )?;

        // println!("out: {:?}", out);
        chip.expose_public(layouter.namespace(|| "out"), &out, 0)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use ff::Field;
    use halo2_proofs::poly::VerificationStrategy;
    use halo2_proofs::transcript::{
        Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, Transcript, TranscriptRead,
        TranscriptReadBuffer, TranscriptWrite, TranscriptWriterBuffer,
    };
    use halo2curves::bn256::{Bn256, Fq};
    use std::marker::PhantomData;

    use super::MyCircuit;
    use crate::proof::{common, create_proof, verify_proof};
    use ff::{FromUniformBytes, WithSmallOrderMulGroup};
    use halo2_proofs::dev::MockProver;
    use halo2_proofs::plonk::{
        create_proof as create_proof_plonk, keygen_pk, keygen_vk,
        verify_proof as verify_proof_plonk, ProvingKey, VerifyingKey,
    };
    use halo2_proofs::poly::commitment::{CommitmentScheme, ParamsProver, Prover, Verifier};
    use pasta_curves::pallas;
    use rand_core::{OsRng, RngCore};

    #[test]
    fn add_scalar_small() {
        let k = 5;

        // let scalar = pallas::Base::from(1);
        // let value = pallas::Base::from(1);
        // let nrows = 10;
        // let out = pallas::Base::from(10);
        let scalar = Fq::from(1);
        let value = Fq::from(1);
        let nrows = 10;
        let out = Fq::from(10);
        // println!("out: {:?}", out);

        let circuit = MyCircuit {
            value,
            scalar,
            nrows,
            _marker: PhantomData,
        };

        // let public_input = vec![out];
        let public_input = vec![out];

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }
    #[test]
    #[ignore = "takes a while"]
    fn add_scalar_big() {
        let k = 20;

        let scalar = Fq::from(1);
        let value = Fq::from(1);
        let nrows = 1_000_000;
        // let out = Fq::from(10);
        let out = Fq::from(1_000_000);
        // println!("out: {:?}", out);

        let circuit = MyCircuit {
            value,
            scalar,
            nrows,
            _marker: PhantomData,
        };

        // let public_input = vec![out];
        let public_input = vec![out];

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }

    #[test]
    fn add_scalar_small_ipa() {
        use halo2_proofs::poly::commitment::CommitmentScheme;
        use halo2_proofs::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
        use halo2_proofs::poly::ipa::multiopen::{ProverIPA, VerifierIPA};
        use halo2_proofs::poly::ipa::strategy::AccumulatorStrategy;
        use halo2curves::pasta::EqAffine;
        use rand_core::OsRng;

        let k = 5;

        type Scheme = IPACommitmentScheme<EqAffine>;

        let scalar = <Scheme as CommitmentScheme>::Scalar::from(1);
        let value = <Scheme as CommitmentScheme>::Scalar::from(1);
        let nrows = 10u64;
        let out = <Scheme as CommitmentScheme>::Scalar::from(nrows);

        // println!("Starting circuit instantiation");
        // println!("out: {:?}", out);

        let circuit = MyCircuit {
            value,
            scalar,
            nrows: nrows as usize,
            _marker: PhantomData,
        };

        // println!("Circuit defined");

        let public_input = vec![out];
        // let public_input = vec![];

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();

        // println!("Prover has run");

        prover.assert_satisfied();

        // println!("Prover satisfied");

        let params = ParamsIPA::<EqAffine>::new(k);

        println!("before keygen");

        // let empty_circuit = MyCircuit::<Fr>::default();

        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");

        println!("Vk generated");

        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        println!("Pk generated");

        let rng = OsRng;

        let proof = create_proof::<_, ProverIPA<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
            rng, &params, &pk, circuit, nrows, k,
        );
        println!("Proof generated with {:?} bytes", proof.len());
        assert_eq!(proof.len(), 1568);
        println!("Proof generated with {:?} bytes", proof.len());

        let verifier_params = params.verifier_params();
        // println!("verifier params generated {:?}", verifier_params);
        verify_proof::<
            _,
            VerifierIPA<_>,
            _,
            Blake2bRead<_, _, Challenge255<_>>,
            AccumulatorStrategy<_>,
        >(verifier_params, pk.get_vk(), &proof[..], nrows);
    }
    #[test]
    fn add_scalar_small_kzg() {
        use halo2_proofs::poly::commitment::CommitmentScheme;
        use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
        use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
        use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
        use halo2curves::bn256::Bn256;
        use halo2curves::bn256::Fr;
        use rand_core::OsRng;

        let k = 5;

        type Scheme = KZGCommitmentScheme<Bn256>;

        let scalar = <Scheme as CommitmentScheme>::Scalar::from(1);
        let value = <Scheme as CommitmentScheme>::Scalar::from(1);
        let nrows = 10u64;
        let out = <Scheme as CommitmentScheme>::Scalar::from(nrows);

        // println!("Starting circuit instantiation");
        println!("out: {:?}", out);

        let circuit = MyCircuit {
            value,
            scalar,
            nrows: nrows as usize,
            _marker: PhantomData,
        };

        // println!("Circuit defined");

        let public_input = vec![out];
        // let public_input = vec![];

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();

        // println!("Prover has run");

        prover.assert_satisfied();

        // println!("Prover satisfied");

        let params = ParamsKZG::<Bn256>::new(k);

        // println!("before keygen");

        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");

        // println!("Vk generated");

        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        // println!("Pk generated");

        let rng = OsRng;

        let proof = create_proof::<_, ProverSHPLONK<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
            rng, &params, &pk, circuit, nrows, k,
        );
        println!("Proof generated with {:?} bytes", proof.len());
        assert_eq!(proof.len(), 992);

        let verifier_params = params.verifier_params();
        // println!("verifier params generated {:?}", verifier_params);
        verify_proof::<
            _,
            VerifierSHPLONK<_>,
            _,
            Blake2bRead<_, _, Challenge255<_>>,
            AccumulatorStrategy<_>,
        >(verifier_params, pk.get_vk(), &proof[..], nrows);
    }
    #[test]
    #[ignore = "takes a while ~ 6min on my machine"]
    fn add_scalar_big_kzg() {
        use halo2_proofs::poly::commitment::CommitmentScheme;
        use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
        use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
        use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy;
        use halo2curves::bn256::Bn256;
        use rand_core::OsRng;

        let k = 20;

        type Scheme = KZGCommitmentScheme<Bn256>;

        let scalar = <Scheme as CommitmentScheme>::Scalar::from(1);
        let value = <Scheme as CommitmentScheme>::Scalar::from(1);
        let nrows = 1_000_000u64;
        let out = <Scheme as CommitmentScheme>::Scalar::from(nrows);

        let circuit = MyCircuit {
            value,
            scalar,
            nrows: nrows as usize,
            _marker: PhantomData,
        };

        let public_input = vec![out];

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();

        prover.assert_satisfied();

        let params = ParamsKZG::<Bn256>::new(k);
        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        let rng = OsRng;

        let proof = create_proof::<_, ProverSHPLONK<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
            rng, &params, &pk, circuit, nrows, k,
        );
        // println!("Proof generated {:?}", proof);
        println!("Proof generated with {:?} bytes", proof.len());
        assert_eq!(proof.len(), 992);

        let verifier_params = params.verifier_params();
        // println!("verifier params generated {:?}", verifier_params);
        verify_proof::<
            _,
            VerifierSHPLONK<_>,
            _,
            Blake2bRead<_, _, Challenge255<_>>,
            AccumulatorStrategy<_>,
        >(verifier_params, pk.get_vk(), &proof[..], nrows);
        // assert!(false);
    }
    #[test]
    #[ignore = "takes a while ~ 52min on my machine"]
    fn add_scalar_big_ipa() {
        use halo2_proofs::poly::commitment::CommitmentScheme;
        use halo2_proofs::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
        use halo2_proofs::poly::ipa::multiopen::{ProverIPA, VerifierIPA};
        use halo2_proofs::poly::ipa::strategy::AccumulatorStrategy;
        use halo2curves::pasta::EqAffine;
        use rand_core::OsRng;

        let k = 20;

        type Scheme = IPACommitmentScheme<EqAffine>;

        let scalar = <Scheme as CommitmentScheme>::Scalar::from(1);
        let value = <Scheme as CommitmentScheme>::Scalar::from(1);
        let nrows = 1_000_000u64;
        let out = <Scheme as CommitmentScheme>::Scalar::from(nrows);

        let circuit = MyCircuit {
            value,
            scalar,
            nrows: nrows as usize,
            _marker: PhantomData,
        };

        let public_input = vec![out];

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();

        prover.assert_satisfied();

        let params = ParamsIPA::<EqAffine>::new(k);

        let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
        let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

        let rng = OsRng;

        let proof = create_proof::<_, ProverIPA<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
            rng, &params, &pk, circuit, nrows, k,
        );
        println!("Proof generated with {:?} bytes", proof.len());
        assert_eq!(proof.len(), 2528);

        let verifier_params = params.verifier_params();
        // println!("verifier params generated {:?}", verifier_params);
        verify_proof::<
            _,
            VerifierIPA<_>,
            _,
            Blake2bRead<_, _, Challenge255<_>>,
            AccumulatorStrategy<_>,
        >(verifier_params, pk.get_vk(), &proof[..], nrows);
        assert!(false);
    }

    // #[cfg(feature = "dev-graph")]
    #[test]
    #[ignore = "only for debug"]
    fn plot_fibonacci1() {
        use plotters::prelude::*;

        let scalar = pallas::Base::from(1);
        let value = pallas::Base::from(1);
        let nrows = 10;
        // let out = pallas::Base::from(11);

        let root = BitMapBackend::new("add-1-layout.png", (1024, 3096)).into_drawing_area();
        // root.fill(&WHITE).unwrap();
        let root = root.titled("Fib 1 Layout", ("sans-serif", 60)).unwrap();

        // let circuit = MyCircuit::<Fp>(PhantomData);
        let circuit = MyCircuit {
            value,
            scalar,
            nrows,
            _marker: PhantomData,
        };
        halo2_proofs::dev::CircuitLayout::default()
            .render(4, &circuit, &root)
            .unwrap();
    }
}
