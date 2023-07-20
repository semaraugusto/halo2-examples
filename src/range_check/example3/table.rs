use std::marker::PhantomData;

use ff::PrimeFieldBits;
use halo2_proofs::{plonk::TableColumn, arithmetic::{Field}, circuit::{Layouter, Value}, plonk::{Error, ConstraintSystem}};

#[derive(Clone, Debug)]
pub(super) struct RangeCheckTable<const RANGE: usize, const NUM_BITS: usize, F: PrimeFieldBits> {
    pub(super) value: TableColumn,
    pub(super) num_bits: TableColumn,
    _marker: PhantomData<F>
}

impl<const RANGE: usize, const NUM_BITS: usize, F: PrimeFieldBits> RangeCheckTable<RANGE, NUM_BITS, F> {
    pub(super) fn configure(meta: &mut ConstraintSystem<F>) -> Self {
        let value = meta.lookup_table_column();
        let num_bits = meta.lookup_table_column();

        Self {
            value, 
            num_bits,
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
                    table.assign_cell(
                        ||"assign num_bits", 
                        self.value, 
                        offset, 
                        || Value::known(F::from(NUM_BITS as u64))
                    )?;
                    table.assign_cell(
                        ||"assign value", 
                        self.value, 
                        offset, 
                        || Value::known(F::from(value as u64))
                    )?;
                    offset += 1;
                }
                // for value in 0..RANGE {
                //     table.assign_cell(
                //         ||"assign cell", 
                //         self.value, 
                //         offset, 
                //         || Value::known(F::from(value as u64))
                //     )?;
                //     offset += 1;
                // }
                Ok(())
        })
    }
}
