use std::marker::PhantomData;

use ff::PrimeFieldBits;
use halo2_proofs::{plonk::TableColumn, arithmetic::{Field}, circuit::{Layouter, Value}, plonk::{Error, ConstraintSystem}};

/// A lookup table for values of NUM_BITS length
/// e.g. RANGE = 1024, values = [0..1023]

#[derive(Clone, Debug)]
pub(super) struct RangeCheckTable<const RANGE: usize, F: PrimeFieldBits> {
    pub(super) value: TableColumn,
    _marker: PhantomData<F>
}

impl<const RANGE: usize, F: PrimeFieldBits> RangeCheckTable<RANGE, F> {
    pub(super) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let value = meta.lookup_table_column();

        Self {
            value, 
            _marker: PhantomData
        }
    }

    pub(super) fn load(
        &self, 
        layouter: &mut impl Layouter<F>
    ) -> Result<(), Error> {
        layouter.assign_table(
            || "load range-check table", 
            |mut table| {
                let mut offset = 0;
                for value in 0..RANGE {
                    println!("Loading: {value:?}");
                    table.assign_cell(
                        ||"num_bits", 
                        self.value, 
                        offset, 
                        || Value::known(F::from(value as u64))
                    )?;
                    offset += 1;
                }
                Ok(())
        })
    }
}
