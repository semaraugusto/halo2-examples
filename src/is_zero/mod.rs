use halo2_proofs::{arithmetic::Field, circuit::*, plonk::*, poly::Rotation};

pub struct IsZeroConfig<F: Field> {
    pub value_inv: Column<Advice>,
    pub expr: Expression<F>,
}

pub struct IsZeroChip<F: Field> {
    pub config: IsZeroConfig<F>,
}

impl<F: Field> IsZeroChip<F> {
    pub fn construct(config: IsZeroConfig<F>) -> Self {
        Self { config }
    }
    pub fn configure(
        meta: &mut ConstraintSystem<F>,
        q_enable: impl FnOnce(&mut VirtualCells<'_, F>) -> Expression<F>,
        value: Column<Advice>,
        value_inv: Column<Advice>,
    ) -> IsZeroConfig<F> {
        let mut expr = Expression::Constant(F::ZERO);
        meta.create_gate("is_zero", |meta| {
            // let selector = meta.query_selector(config.selector);
            let selector = q_enable(meta);
            let value = meta.query_advice(value, Rotation::cur());
            let value_inv = meta.query_advice(value_inv, Rotation::cur());

            expr = Expression::Constant(F::ONE) - value.clone() * value_inv.clone();
            vec![selector * value * expr.clone()]
        });
        IsZeroConfig { value_inv, expr }
    }

    pub fn assign(
        &self,
        mut layouter: impl Layouter<F>,
        value: Value<Assigned<F>>,
    ) -> Result<Expression<F>, Error> {
        layouter.assign_region(
            || "is_zero_chip",
            //
            |mut region| {
                let value_inv = value.clone().invert();

                region.assign_advice(|| "value inv", self.config.value_inv, 0, || value_inv)?;
                Ok(self.config.expr.clone())
            },
        )
    }
}
