use ff::Field;
use halo2_proofs::dev::MockProver;
use halo2_proofs::poly::commitment::{CommitmentScheme, ParamsProver, Prover, Verifier};
use halo2_proofs::poly::VerificationStrategy;

use ff::{FromUniformBytes, WithSmallOrderMulGroup};
use halo2_proofs::plonk::{
    create_proof as create_proof_plonk, keygen_pk, keygen_vk, verify_proof as verify_proof_plonk,
    Circuit, ProvingKey, VerifyingKey,
};
use halo2_proofs::transcript::{
    Blake2bRead, Blake2bWrite, Challenge255, EncodedChallenge, Transcript, TranscriptRead,
    TranscriptReadBuffer, TranscriptWrite, TranscriptWriterBuffer,
};
use rand_core::{OsRng, RngCore};

pub fn keygen<Scheme: CommitmentScheme>(
    k: u32,
    circuit: impl Circuit<Scheme::Scalar>,
) -> (
    <Scheme as CommitmentScheme>::ParamsProver,
    ProvingKey<<Scheme as CommitmentScheme>::Curve>,
)
where
    <Scheme as CommitmentScheme>::Scalar: FromUniformBytes<64>,
{
    let params = Scheme::ParamsProver::new(k);
    let vk = keygen_vk(&params, &circuit).expect("keygen_vk should not fail");
    let pk = keygen_pk(&params, vk, &circuit).expect("keygen_pk should not fail");

    (params, pk)
}

pub fn common<Scheme: CommitmentScheme>() -> (
    <Scheme as CommitmentScheme>::Scalar,
    <Scheme as CommitmentScheme>::Scalar,
) {
    let scalar = <Scheme as CommitmentScheme>::Scalar::ONE;
    let value = <Scheme as CommitmentScheme>::Scalar::ONE;

    (scalar, value)
    // common!(Scheme)
}
pub fn verify_proof<
    'a,
    'params,
    Scheme: CommitmentScheme,
    V: Verifier<'params, Scheme>,
    E: EncodedChallenge<Scheme::Curve>,
    T: TranscriptReadBuffer<&'a [u8], Scheme::Curve, E>,
    Strategy: VerificationStrategy<'params, Scheme, V, Output = Strategy>,
>(
    params_verifier: &'params Scheme::ParamsVerifier,
    vk: &VerifyingKey<Scheme::Curve>,
    proof: &'a [u8],
    nrows: u64,
) where
    Scheme::Scalar: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    // let (scalar, value) = common::<Scheme>();
    let out = Scheme::Scalar::from(nrows);

    let pubinputs = vec![out];

    let mut transcript = T::init(proof);

    let strategy = Strategy::new(params_verifier);
    let strategy = verify_proof_plonk(
        params_verifier,
        vk,
        strategy,
        &[&[&pubinputs[..]], &[&pubinputs[..]]],
        &mut transcript,
    )
    .unwrap();

    assert!(strategy.finalize());
}

pub fn create_proof<
    'params,
    Scheme: CommitmentScheme,
    P: Prover<'params, Scheme>,
    E: EncodedChallenge<Scheme::Curve>,
    R: RngCore,
    T: TranscriptWriterBuffer<Vec<u8>, Scheme::Curve, E>,
>(
    rng: R,
    params: &'params Scheme::ParamsProver,
    pk: &ProvingKey<Scheme::Curve>,
    circuit: impl Circuit<Scheme::Scalar> + Clone,
    nrows: u64,
    k: u32,
) -> Vec<u8>
where
    Scheme::Scalar: Ord + WithSmallOrderMulGroup<3> + FromUniformBytes<64>,
{
    let out = Scheme::Scalar::from(nrows);

    let mut transcript = T::init(vec![]);

    create_proof_plonk::<Scheme, P, _, _, _, _>(
        params,
        pk,
        &[circuit.clone(), circuit.clone()],
        &[&[&[out]], &[&[out]]],
        rng,
        &mut transcript,
    )
    .expect("proof generation should not fail");

    // Check this circuit is satisfied.
    let prover = match MockProver::run(k, &circuit, vec![vec![out]]) {
        Ok(prover) => prover,
        Err(e) => panic!("{:?}", e),
    };
    assert_eq!(prover.verify(), Ok(()));

    transcript.finalize()
}
