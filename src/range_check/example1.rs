use ff::{Field, PrimeField};
use halo2_gadgets::utilities::{FieldValue, UtilitiesInstructions};
use halo2_proofs::{circuit::*, plonk::*, poly::Rotation};
use pasta_curves::pallas;
use std::marker::PhantomData;

// Table setup
//
//
//     value   |   q_range_check
// ------------------------------------
//        v    |        1

/// A type representing a range-constrained field element.
#[derive(Clone, Debug)]
pub struct RangeConstrained<F: Field, T: FieldValue<F>> {
    inner: T,
    num_bits: usize,
    _phantom: PhantomData<F>,
}

impl<F: Field, T: FieldValue<F>> RangeConstrained<F, T> {
    /// Returns the range-constrained inner type.
    pub fn inner(&self) -> &T {
        &self.inner
    }

    /// Returns the number of bits to which this cell is constrained.
    pub fn num_bits(&self) -> usize {
        self.num_bits
    }
}
impl<F: Field> RangeConstrained<F, AssignedCell<F, F>> {
    /// Constructs a `RangeConstrained<AssignedCell<F, F>>` without verifying that the
    /// cell is correctly range constrained.
    ///
    /// This API only exists to ease with integrating this type into existing circuits,
    /// and will likely be removed in future.
    pub fn unsound_unchecked(cell: AssignedCell<F, F>, num_bits: usize) -> Self {
        Self {
            inner: cell,
            num_bits,
            _phantom: PhantomData::default(),
        }
    }

    /// Extracts the range-constrained value from this range-constrained cell.
    pub fn value(&self) -> RangeConstrained<F, Value<F>> {
        RangeConstrained {
            inner: self.inner.value().copied(),
            num_bits: self.num_bits,
            _phantom: PhantomData::default(),
        }
    }
}

/// Checks that an expression is either 1 or 0.
pub fn bool_check<F: PrimeField>(value: Expression<F>) -> Expression<F> {
    range_check(value, 2)
}

/// Check that an expression is in the small range [0..range),
/// i.e. 0 ≤ word < range.
pub fn range_check<F: PrimeField>(word: Expression<F>, range: usize) -> Expression<F> {
    (1..range).fold(word.clone(), |acc, i| {
        acc * (Expression::Constant(F::from(i as u64)) - word.clone())
    })
}

struct MyCircuit<const RANGE: usize>(u8);

impl<const RANGE: usize> UtilitiesInstructions<pallas::Base> for MyCircuit<RANGE> {
    type Var = AssignedCell<pallas::Base, pallas::Base>;
}

#[derive(Clone)]
struct Config {
    selector: Selector,
    advice: Column<Advice>,
}

impl<const RANGE: usize> Circuit<pallas::Base> for MyCircuit<RANGE> {
    type Config = Config;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        MyCircuit(self.0)
    }

    fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
        let selector = meta.selector();
        let advice = meta.advice_column();

        meta.create_gate("range check", |meta| {
            let selector = meta.query_selector(selector);
            let advice = meta.query_advice(advice, Rotation::cur());

            Constraints::with_selector(selector, Some(range_check(advice, RANGE)))
        });

        Config { selector, advice }
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<pallas::Base>,
    ) -> Result<(), Error> {
        layouter.assign_region(
            || "range constrain",
            |mut region| {
                config.selector.enable(&mut region, 0)?;
                region.assign_advice(
                    || format!("witness {}", self.0),
                    config.advice,
                    0,
                    || Value::known(pallas::Base::from(self.0 as u64)),
                )?;
                Ok(())
            },
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use halo2_proofs::{
        dev::{FailureLocation, MockProver, VerifyFailure},
        plonk::Any,
    };
    use pasta_curves::pallas;

    #[test]
    fn test_range_check() {
        for i in 0..8 {
            let circuit: MyCircuit<8> = MyCircuit(i);
            let prover = MockProver::<pallas::Base>::run(3, &circuit, vec![]).unwrap();
            assert_eq!(prover.verify(), Ok(()));
        }

        {
            let circuit: MyCircuit<8> = MyCircuit(8);
            let prover = MockProver::<pallas::Base>::run(3, &circuit, vec![]).unwrap();
            assert_eq!(
                prover.verify(),
                Err(vec![VerifyFailure::ConstraintNotSatisfied {
                    constraint: ((0, "range check").into(), 0, "").into(),
                    location: FailureLocation::InRegion {
                        region: (0, "range constrain").into(),
                        offset: 0,
                    },

                    cell_values: vec![(
                        ((Any::Advice(Advice::default()), 0usize).into(), 0).into(),
                        "0x8".to_string()
                    )]
                }]),
            );
        }
    }
}
