use criterion::{black_box, criterion_group, criterion_main, Criterion};
use ff::{Field, FromUniformBytes};
use halo2_proofs::poly::ipa::strategy::AccumulatorStrategy as IPAAccumulatorStrategy;
use halo2_proofs::poly::kzg::strategy::AccumulatorStrategy as KZGAccumulatorStrategy;
use halo2curves::bn256::{Bn256, Fq, Fr};
use std::marker::PhantomData;
// use mycrate::fibonacci;
use halo2_examples::add1::example1::MyCircuit;
use halo2_examples::proof::{create_proof, keygen, verify_proof};
use halo2_proofs::dev::MockProver;
use halo2_proofs::poly::commitment::{CommitmentScheme, ParamsProver, Prover, Verifier};
use halo2_proofs::poly::ipa::commitment::{IPACommitmentScheme, ParamsIPA};
use halo2_proofs::poly::ipa::multiopen::{ProverIPA, VerifierIPA};
use halo2_proofs::poly::kzg::commitment::{KZGCommitmentScheme, ParamsKZG};
use halo2_proofs::poly::kzg::multiopen::{ProverSHPLONK, VerifierSHPLONK};
use halo2_proofs::poly::VerificationStrategy;
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, Transcript, TranscriptRead,
    TranscriptReadBuffer, TranscriptWrite, TranscriptWriterBuffer,
};
use halo2curves::pasta::EqAffine;
use halo2curves::pasta::Fp;
use rand_core::{OsRng, RngCore};

fn mock_test_circuit<Scheme: CommitmentScheme>(
    k: u32,
    out: Scheme::Scalar,
    circuit: MyCircuit<<Scheme as CommitmentScheme>::Scalar>,
) where
    <Scheme as CommitmentScheme>::Scalar: Ord, // F: From<u64>,
    <Scheme as CommitmentScheme>::Scalar: FromUniformBytes<64>, // F: From<u64>,
{
    let public_input = vec![out];

    let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();

    prover.assert_satisfied();
}

pub fn criterion_benchmark(c: &mut Criterion) {
    // Constants
    let small_k = 5;
    let big_k = 16;
    let scalar = 1;
    let value = 1;
    let small_nrows = 10;
    let big_nrows = 65500;
    let rng = OsRng;

    // Generate Small IPA proof
    type IPAField = EqAffine;
    type IPAScheme = IPACommitmentScheme<IPAField>;
    let ipa_scalar = <IPAScheme as CommitmentScheme>::Scalar::from(scalar);
    let ipa_value = <IPAScheme as CommitmentScheme>::Scalar::from(value);
    let ipa_small_out = <IPAScheme as CommitmentScheme>::Scalar::from(small_nrows);
    let ipa_big_out = <IPAScheme as CommitmentScheme>::Scalar::from(big_nrows);
    let ipa_small_circuit = MyCircuit {
        value: ipa_value,
        scalar: ipa_scalar,
        nrows: small_nrows as usize,
        _marker: PhantomData,
    };
    let (ipa_small_params, ipa_small_pk) = keygen::<IPAScheme>(small_k, ipa_small_circuit.clone());

    let ipa_small_proof = create_proof::<_, ProverIPA<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
        rng,
        &ipa_small_params,
        &ipa_small_pk,
        ipa_small_circuit.clone(),
        small_nrows,
        small_k,
    );

    // Generate Big IPA proof
    let ipa_big_circuit = MyCircuit {
        value: ipa_value,
        scalar: ipa_scalar,
        nrows: big_nrows as usize,
        _marker: PhantomData,
    };
    let (ipa_big_params, ipa_big_pk) = keygen::<IPAScheme>(big_k, ipa_big_circuit.clone());

    let ipa_big_proof = create_proof::<_, ProverIPA<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
        rng,
        &ipa_big_params,
        &ipa_big_pk,
        ipa_big_circuit.clone(),
        big_nrows,
        big_k,
    );

    // Generate Small KZG proof
    type KZGField = Bn256;
    type KZGScheme = KZGCommitmentScheme<KZGField>;

    let kzg_scalar = <KZGScheme as CommitmentScheme>::Scalar::from(scalar);
    let kzg_value = <KZGScheme as CommitmentScheme>::Scalar::from(value);
    let kzg_small_out = <KZGScheme as CommitmentScheme>::Scalar::from(small_nrows);
    let kzg_big_out = <KZGScheme as CommitmentScheme>::Scalar::from(big_nrows);
    let kzg_small_circuit = MyCircuit {
        value: kzg_value,
        scalar: kzg_scalar,
        nrows: small_nrows as usize,
        _marker: PhantomData,
    };
    let (kzg_small_params, kzg_small_pk) = keygen::<KZGScheme>(small_k, kzg_small_circuit.clone());
    let kzg_small_proof =
        create_proof::<_, ProverSHPLONK<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
            rng,
            &kzg_small_params,
            &kzg_small_pk,
            kzg_small_circuit.clone(),
            small_nrows,
            small_k,
        );

    // Generate Big KZG proof
    let kzg_big_circuit = MyCircuit {
        value: kzg_value,
        scalar: kzg_scalar,
        nrows: big_nrows as usize,
        _marker: PhantomData,
    };
    let (kzg_big_params, kzg_big_pk) = keygen::<KZGScheme>(big_k, kzg_big_circuit.clone());
    let kzg_big_proof =
        create_proof::<_, ProverSHPLONK<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
            rng,
            &kzg_big_params,
            &kzg_big_pk,
            kzg_big_circuit.clone(),
            big_nrows,
            big_k,
        );

    // Generate (small) KZG Verifier params
    let kzg_small_verifier_params = kzg_small_params.verifier_params();
    // Generate (big) KZG Verifier params
    let kzg_big_verifier_params = kzg_big_params.verifier_params();

    // Generate (small) IPA Verifier params
    let ipa_small_verifier_params: &<IPAScheme as CommitmentScheme>::ParamsVerifier =
        ipa_small_params.verifier_params();
    // Generate (big) IPA Verifier params
    let ipa_big_verifier_params: &<IPAScheme as CommitmentScheme>::ParamsVerifier =
        ipa_big_params.verifier_params();
    // let kzg_small_proof =
    //     create_proof::<_, ProverSHPLONK<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
    //         rng,
    //         &kzg_small_params,
    //         &kzg_small_pk,
    //         kzg_small_circuit.clone(),
    //         small_nrows,
    //         small_k,
    //     );

    c.bench_function("mock_test_circuit_rows_small_IPA", |b| {
        b.iter(|| {
            mock_test_circuit::<IPAScheme>(
                black_box(small_k),
                black_box(ipa_small_out),
                black_box(ipa_small_circuit.clone()),
            )
        })
    });
    c.bench_function("mock_test_circuit_rows_big_IPA", |b| {
        b.iter(|| {
            mock_test_circuit::<IPAScheme>(
                black_box(big_k),
                black_box(ipa_big_out),
                black_box(ipa_big_circuit.clone()),
            )
        })
    });
    c.bench_function("mock_test_circuit_rows_small_kzg", |b| {
        b.iter(|| {
            mock_test_circuit::<KZGScheme>(
                black_box(small_k),
                black_box(kzg_small_out),
                black_box(kzg_small_circuit.clone()),
            )
        })
    });
    c.bench_function("mock_test_circuit_rows_big_kzg", |b| {
        b.iter(|| {
            mock_test_circuit::<KZGScheme>(
                black_box(big_k),
                black_box(kzg_big_out),
                black_box(kzg_big_circuit.clone()),
            )
        })
    });
    c.bench_function("keygen_small_IPA", |b| {
        b.iter(|| keygen::<IPAScheme>(black_box(small_k), black_box(ipa_small_circuit.clone())))
    });
    c.bench_function("keygen_big_IPA", |b| {
        b.iter(|| keygen::<IPAScheme>(black_box(big_k), black_box(ipa_big_circuit.clone())))
    });
    c.bench_function("keygen_small_KZG", |b| {
        b.iter(|| keygen::<KZGScheme>(black_box(small_k), black_box(kzg_small_circuit.clone())))
    });
    c.bench_function("keygen_big_KZG", |b| {
        b.iter(|| keygen::<KZGScheme>(black_box(big_k), black_box(kzg_big_circuit.clone())))
    });
    c.bench_function("ipa_prover_test_circuit_rows_small", |b| {
        b.iter(|| {
            create_proof::<_, ProverIPA<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
                black_box(rng),
                black_box(&ipa_small_params),
                black_box(&ipa_small_pk),
                black_box(ipa_small_circuit.clone()),
                black_box(small_nrows),
                black_box(small_k),
            )
        })
    });
    c.bench_function("ipa_prover_test_circuit_rows_big", |b| {
        b.iter(|| {
            create_proof::<_, ProverIPA<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
                black_box(rng),
                black_box(&ipa_big_params),
                black_box(&ipa_big_pk),
                black_box(ipa_big_circuit.clone()),
                black_box(big_nrows),
                black_box(big_k),
            )
        })
    });
    c.bench_function("kzg_prover_test_circuit_rows_small", |b| {
        b.iter(|| {
            create_proof::<_, ProverSHPLONK<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
                black_box(rng),
                black_box(&kzg_small_params),
                black_box(&kzg_small_pk),
                black_box(kzg_small_circuit.clone()),
                black_box(small_nrows),
                black_box(small_k),
            )
        })
    });
    c.bench_function("kzg_prover_test_circuit_rows_big", |b| {
        b.iter(|| {
            create_proof::<_, ProverSHPLONK<_>, _, _, Blake2bWrite<_, _, Challenge255<_>>>(
                black_box(rng),
                black_box(&kzg_big_params),
                black_box(&kzg_big_pk),
                black_box(kzg_big_circuit.clone()),
                black_box(big_nrows),
                black_box(big_k),
            )
        })
    });
    c.bench_function("ipa_verifier_test_circuit_rows_small", |b| {
        b.iter(|| {
            verify_proof::<
                _,
                VerifierIPA<_>,
                _,
                Blake2bRead<_, _, Challenge255<_>>,
                IPAAccumulatorStrategy<_>,
            >(
                black_box(ipa_small_verifier_params),
                black_box(ipa_small_pk.get_vk()),
                black_box(&ipa_small_proof[..]),
                black_box(small_nrows),
            );
        })
    });
    c.bench_function("ipa_verifier_test_circuit_rows_big", |b| {
        b.iter(|| {
            verify_proof::<
                _,
                VerifierIPA<_>,
                _,
                Blake2bRead<_, _, Challenge255<_>>,
                IPAAccumulatorStrategy<_>,
            >(
                black_box(ipa_big_verifier_params),
                black_box(ipa_big_pk.get_vk()),
                black_box(&ipa_big_proof[..]),
                black_box(big_nrows),
            );
        })
    });
    c.bench_function("kzg_verifier_test_circuit_rows_small", |b| {
        b.iter(|| {
            verify_proof::<
                _,
                VerifierSHPLONK<_>,
                _,
                Blake2bRead<_, _, Challenge255<_>>,
                KZGAccumulatorStrategy<_>,
            >(
                black_box(kzg_small_verifier_params),
                black_box(kzg_small_pk.get_vk()),
                black_box(&kzg_small_proof[..]),
                black_box(small_nrows),
            );
        })
    });
    c.bench_function("kzg_verifier_test_circuit_rows_big", |b| {
        b.iter(|| {
            verify_proof::<
                _,
                VerifierSHPLONK<_>,
                _,
                Blake2bRead<_, _, Challenge255<_>>,
                KZGAccumulatorStrategy<_>,
            >(
                black_box(kzg_big_verifier_params),
                black_box(kzg_big_pk.get_vk()),
                black_box(&kzg_big_proof[..]),
                black_box(big_nrows),
            );
        })
    });
}

criterion_group!(benches, criterion_benchmark);
criterion_main!(benches);
