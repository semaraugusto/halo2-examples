use halo2_proofs::{arithmetic::Field, circuit::*, plonk::*, poly::Rotation};
use std::marker::PhantomData;

// Table setup
//
// let v = small value range check range: u8 bits
// let v' = big value range check with lookup argument
//
//        a   |   b   |   c  |  selector  |
// -------------------------------------------------------------------
//  1:      F(0) |  F(1) | F(2) |      1     |
//  2:      F(1) |  F(2) | F(3) |      1     |
//  3:      F(2) |  F(3) | F(4) |      1     |
//  4:      F(3) |  F(4) | F(5) |      1     |
//  5:      F(4) |  F(5) | F(6) |      1     |
//  6:      F(5) |  F(6) | F(7) |      1     |
//  7:      F(6) |  F(7) | F(8) |      1     |
//  8:      F(7) |  F(8) | F(9) |      1     |
//  9:      F(8) |  F(9) |F(10) |      1     |
//  10:     F(9) | F(10) |F(11) |      1     |

#[derive(Clone, Debug)]
struct FibonacciConfig {
    pub advice: [Column<Advice>; 3],
    pub selector: Selector,
    pub instance: Column<Instance>,
}

#[derive(Clone, Debug)]
struct FibonacciChip<F: Field> {
    config: FibonacciConfig,
    _marker: PhantomData<F>,
}

type AssignedRow<F> = (AssignedCell<F, F>, AssignedCell<F, F>, AssignedCell<F, F>);

impl<F: Field> FibonacciChip<F> {
    pub fn construct(config: FibonacciConfig) -> Self {
        Self {
            config,
            _marker: PhantomData,
        }
    }

    pub fn configure(meta: &mut ConstraintSystem<F>) -> FibonacciConfig {
        let a = meta.advice_column();
        let b = meta.advice_column();
        let c = meta.advice_column();
        let selector = meta.selector();
        let instance = meta.instance_column();

        meta.enable_equality(a);
        meta.enable_equality(b);
        meta.enable_equality(c);
        meta.enable_equality(instance);

        meta.create_gate("add", |meta| {
            let selector = meta.query_selector(selector);
            let a = meta.query_advice(a, Rotation::cur());
            let b = meta.query_advice(b, Rotation::cur());
            let c = meta.query_advice(c, Rotation::cur());

            vec![selector * (a + b - c)]
        });

        FibonacciConfig {
            advice: [a, b, c],
            selector,
            instance,
        }
    }

    pub fn assign_initial_values(
        &self,
        mut layouter: impl Layouter<F>,
    ) -> Result<AssignedRow<F>, Error> {
        layouter.assign_region(
            || "initial values",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                let a_cell = region.assign_advice_from_instance(
                    || "a0",
                    self.config.instance,
                    0,
                    self.config.advice[0],
                    0,
                )?;

                let b_cell = region.assign_advice_from_instance(
                    || "a1",
                    self.config.instance,
                    1,
                    self.config.advice[1],
                    0,
                )?;

                let c_cell = region.assign_advice(
                    || "a + b",
                    self.config.advice[2],
                    0,
                    || a_cell.value().copied() + b_cell.value(),
                )?;

                Ok((a_cell, b_cell, c_cell))
            },
        )
    }
    pub fn assign_row(
        &self,
        mut layouter: impl Layouter<F>,
        prev_b: &AssignedCell<F, F>,
        prev_c: &AssignedCell<F, F>,
    ) -> Result<AssignedCell<F, F>, Error> {
        layouter.assign_region(
            || "next row",
            |mut region| {
                self.config.selector.enable(&mut region, 0)?;

                prev_b.copy_advice(|| "a0", &mut region, self.config.advice[0], 0)?;

                prev_c.copy_advice(|| "a1", &mut region, self.config.advice[1], 0)?;

                let c_cell = region.assign_advice(
                    || "a0 + a1",
                    self.config.advice[2],
                    0,
                    || prev_b.value().copied() + prev_c.value(),
                )?;

                Ok(c_cell)
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
struct MyCircuit<F>(PhantomData<F>);

impl<F: Field> Circuit<F> for MyCircuit<F> {
    type Config = FibonacciConfig;
    type FloorPlanner = SimpleFloorPlanner;

    fn without_witnesses(&self) -> Self {
        Self::default()
    }

    fn configure(meta: &mut ConstraintSystem<F>) -> Self::Config {
        FibonacciChip::configure(meta)
    }

    fn synthesize(
        &self,
        config: Self::Config,
        mut layouter: impl Layouter<F>,
    ) -> Result<(), Error> {
        let chip = FibonacciChip::<F>::construct(config);
        let (_, b, c) = chip.assign_initial_values(layouter.namespace(|| "initial values"))?; // (F(0), F(1), F(2))
        let mut prev_b = b;
        let mut prev_c = c;
        for _ in 3..10 {
            let c_cell = chip.assign_row(layouter.namespace(|| "next row"), &prev_b, &prev_c)?; // F(i)

            prev_b = prev_c;
            prev_c = c_cell;
        }
        println!("prev_c: {:?}", prev_c);
        chip.expose_public(layouter.namespace(|| "out"), &prev_c, 2)?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::marker::PhantomData;

    use super::MyCircuit;
    use halo2_proofs::dev::MockProver;
    use pasta_curves::pallas;

    #[test]
    fn fibonacci_example_small() {
        let k = 5;

        let a = pallas::Base::from(1); // F[0]
        let b = pallas::Base::from(1); // F[1]
        let out = pallas::Base::from(55); // F[9]

        let circuit = MyCircuit(PhantomData);

        let public_input = vec![a, b, out];

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }
    #[test]
    #[ignore = "takes a while"]
    fn fibonacci_example_big() {
        let k = 5;

        let a = pallas::Base::from(1); // F[0]
        let b = pallas::Base::from(1); // F[1]
        let out = pallas::Base::from(55); // F[9]

        let circuit = MyCircuit(PhantomData);

        let public_input = vec![a, b, out];

        let prover = MockProver::run(k, &circuit, vec![public_input.clone()]).unwrap();
        prover.assert_satisfied();
    }
}
