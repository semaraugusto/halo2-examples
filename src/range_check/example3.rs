// use ff::{Field, PrimeField, PrimeFieldBits};
// use halo2_proofs::{
//     circuit::*,
//     plonk::*,
//     poly::Rotation,
//
// };
// use halo2_gadgets::utilities::{UtilitiesInstructions, FieldValue};
// use pasta_curves::pallas;
// use std::marker::PhantomData;
//
// // Table setup
// //
// // let v = small value range check range: u8 bits
// // let v' = big value range check with lookup argument
// //
// //     value   |   q_range_check   |  q_lookup  |  table_value  |
// // -------------------------------------------------------------------
// //        v    |        1          |      0     |       0       |
// //        v'   |        0          |      1     |       1       |
//
//
// mod table;
// use table::RangeCheckTable;
// // use super::example1::{RangeConstrained, bool_check};
//
// #[derive(Debug, Clone)]
// /// A range-constrained value in the circuit produced by the RangeCheckConfig.
// struct RangeConstrained<F: Field, const RANGE: usize>(AssignedCell<Assigned<F>, F>);
// /// A type representing a range-constrained field element.
// #[derive(Clone)]
// struct RangeCheckConfig<const RANGE: usize, const NUM_BITS: usize, const LOOKUP_RANGE: usize, F: PrimeFieldBits> {
//     q_range_check: Selector,
//     q_lookup: Selector,
//     advice: Column<Advice>,
//     table: RangeCheckTable<LOOKUP_RANGE, NUM_BITS, F>
// }
//
// impl<const RANGE: usize, const NUM_BITS: usize, const LOOKUP_RANGE: usize, F: PrimeFieldBits> RangeCheckConfig<RANGE, NUM_BITS, LOOKUP_RANGE, F> {
//     fn configure(meta: &mut ConstraintSystem<F>, advice: Column<Advice>) -> Self {
//         // Toggles range check constraint
//         let q_range_check = meta.selector();
//
//         // Toggles lookup constraint
//         let q_lookup = meta.complex_selector();
//
//         // Config lookup table
//         let table = RangeCheckTable::configure(meta);
//
//         // Small range check
//         meta.create_gate("range check", |meta| {
//             let selector = meta.query_selector(q_range_check);
//             let advice = meta.query_advice(advice, Rotation::cur());
//
//             let range_check = |value: Expression<F>, range: usize| {
//                 assert!(range > 0);
//                 (1..range).fold(value.clone(), |expr, i| {
//                     expr * (Expression::Constant(F::from(i as u64)) - value.clone())
//                 })
//             };
//
//             Constraints::with_selector(selector, [("range check", range_check(advice, RANGE))])
//         });
//
//         // lookup range check
//         meta.lookup(|meta| {
//             let q_lookup = meta.query_selector(q_lookup);
//             let advice = meta.query_advice(advice, Rotation::cur());
//
//             vec![
//                 (q_lookup * advice, table.value)
//             ]
//         });
//
//         Self { q_range_check, q_lookup, advice, table }
//     }
//     pub fn assign_simple(
//         &self,
//         mut layouter: impl Layouter<F>,
//         advice: Value<Assigned<F>>,
//     ) -> Result<RangeConstrained<F, RANGE>, Error> {
//         layouter.assign_region(
//             || "Assign value for simple range check",
//             |mut region| {
//                 let offset = 0;
//
//                 // Enable q_range_check
//                 self.q_range_check.enable(&mut region, offset)?;
//
//                 // Assign value
//                 region
//                     .assign_advice(|| "value", self.advice, offset, || advice)
//                     .map(RangeConstrained)
//             },
//         )
//     }
//
//     pub fn assign_lookup(
//         &self,
//         mut layouter: impl Layouter<F>,
//         advice: Value<Assigned<F>>,
//     ) -> Result<RangeConstrained<F, LOOKUP_RANGE>, Error> {
//         layouter.assign_region(
//             || "Assign value for lookup range check",
//             |mut region| {
//                 let offset = 0;
//
//                 // Enable q_lookup
//                 self.q_lookup.enable(&mut region, offset)?;
//
//                 // Assign value
//                 region
//                     .assign_advice(|| "value", self.advice, offset, || advice)
//                     .map(RangeConstrained)
//             },
//         )
//     }
// }
//
// #[cfg(test)]
// mod tests {
//     use super::*;
//     // use group::ff::{Field, FromUniformBytes, PrimeField};
//     use halo2_proofs::{
//         circuit::{Layouter, SimpleFloorPlanner},
//         dev::{FailureLocation, MockProver, VerifyFailure},
//         plonk::{Any, Circuit, ConstraintSystem, Error},
//     };
//     use pasta_curves::pallas;
//
//         #[derive(Default)]
//     struct MyCircuit<const RANGE: usize, const NUM_BITS: usize, const LOOKUP_RANGE: usize> {
//         value: Value<Assigned<pallas::Base>>,
//         lookup_value: Value<Assigned<pallas::Base>>,
//     }
//
//     impl<const RANGE: usize,const NUM_BITS: usize, const LOOKUP_RANGE: usize> Circuit<pallas::Base>
//     // impl<const RANGE: usize, const LOOKUP_RANGE: usize> Circuit<pallas:Base>
//         for MyCircuit<RANGE, NUM_BITS, LOOKUP_RANGE>
//     {
//         type Config = RangeCheckConfig<RANGE, NUM_BITS, LOOKUP_RANGE, pallas::Base>;
//         type FloorPlanner = SimpleFloorPlanner;
//
//         fn without_witnesses(&self) -> Self {
//             Self::default()
//         }
//
//         fn configure(meta: &mut ConstraintSystem<pallas::Base>) -> Self::Config {
//             let value = meta.advice_column();
//             RangeCheckConfig::configure(meta, value)
//         }
//
//         fn synthesize(
//             &self,
//             config: Self::Config,
//             mut layouter: impl Layouter<pallas::Base>,
//         ) -> Result<(), Error> {
//             config.table.load(&mut layouter)?;
//
//             config.assign_simple(layouter.namespace(|| "Assign simple value"), self.value)?;
//             config.assign_lookup(
//                 layouter.namespace(|| "Assign lookup value"),
//                 self.lookup_value,
//             )?;
//
//             Ok(())
//         }
//     }
//     #[test]
//     fn test_range_check_lookup() {
//         let k = 9;
//         const RANGE: usize = 8;
//         const NUM_BITS: usize = 8;
//         const LOOKUP_RANGE: usize = 256;
//
//         for i in 0..RANGE {
//             for j in 0..LOOKUP_RANGE {
//                 let circuit = MyCircuit::<RANGE, NUM_BITS, LOOKUP_RANGE> {
//                     value: Value::known(pallas::Base::from(i as u64).into()),
//                     lookup_value: Value::known(pallas::Base::from(j as u64).into()),
//                 };
//                 let prover = MockProver::<pallas::Base>::run(k, &circuit, vec![]).unwrap();
//                 prover.assert_satisfied()
//             }
//         }
//
//         {
//             let circuit = MyCircuit::<RANGE, NUM_BITS, LOOKUP_RANGE> {
//                 value: Value::known(pallas::Base::from(RANGE as u64).into()),
//                 lookup_value: Value::known(pallas::Base::from(LOOKUP_RANGE as u64).into()),
//             };
//             let prover = MockProver::<pallas::Base>::run(k, &circuit, vec![]).unwrap();
//
//             assert_eq!(
//                 prover.verify(),
//                 Err(vec![
//                     VerifyFailure::ConstraintNotSatisfied {
//                         constraint: ((0, "range check").into(), 0, "range check").into(),
//                         location: FailureLocation::InRegion {
//                             region: (1, "Assign value for simple range check").into(),
//                             offset: 0
//                         },
//                         cell_values: vec![(((Any::Advice, 0).into(), 0).into(), "0x8".to_string())]
//                     },
//                     VerifyFailure::Lookup {
//                         lookup_index: 0,
//                         location: FailureLocation::InRegion {
//                             region: (2, "Assign value for lookup range check").into(),
//                             offset: 0
//                         }
//                     }
//                 ])
//             );
//         }
//     }
//     // #[cfg(feature = "dev-graph")]
//     #[test]
//     fn print_range_check_2() {
//         use plotters::prelude::*;
//
//         const RANGE: usize = 8;
//         const NUM_BITS: usize = 8;
//         const LOOKUP_RANGE: usize = 256;
//
//         let root = BitMapBackend::new("range-check-2-layout.png", (1024, 3096)).into_drawing_area();
//         root.fill(&WHITE).unwrap();
//         let root = root
//             .titled("Range Check 2 Layout", ("sans-serif", 60))
//             .unwrap();
//
//         let circuit = MyCircuit::<RANGE, NUM_BITS, LOOKUP_RANGE> {
//             value: Value::unknown(),
//             lookup_value: Value::unknown(),
//         };
//         halo2_proofs::dev::CircuitLayout::default()
//             .render(9, &circuit, &root)
//             .unwrap();
//     }
// }
