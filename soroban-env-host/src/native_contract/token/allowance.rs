use crate::host::Host;
use crate::native_contract::base_types::Address;
use crate::native_contract::contract_error::ContractError;
use crate::native_contract::token::storage_types::{AllowanceDataKey, DataKey};
use crate::{err, HostError};
use soroban_env_common::{Env, StorageType, TryIntoVal};

use super::storage_types::AllowanceValue;

// Metering: covered by components
pub fn read_allowance(e: &Host, from: Address, spender: Address) -> Result<i128, HostError> {
    let key = DataKey::Allowance(AllowanceDataKey { from, spender });
    if let Ok(allowance) = e.get_contract_data(key.try_into_val(e)?, StorageType::Temporary) {
        let val: AllowanceValue = allowance.try_into_val(e)?;
        if val.expiration_ledger <= e.get_ledger_sequence()?.into() {
            Ok(0)
        } else {
            Ok(val.amount)
        }
    } else {
        Ok(0)
    }
}

// Metering: covered by components
pub fn write_allowance(
    e: &Host,
    from: Address,
    spender: Address,
    amount: i128,
    expiration: u32,
) -> Result<(), HostError> {
    let key = DataKey::Allowance(AllowanceDataKey { from, spender });

    // validates the expiration and then returns the ledger seq
    // The expiration can be less than ledger seq if clearing an allowance
    let ledger_seq = e.with_ledger_info(|li| {
        if expiration > li.sequence_number.saturating_add(li.max_entry_expiration) {
            Err(err!(
                e,
                ContractError::AllowanceError,
                "expiration is greater than max: {} > {}",
                expiration,
                li.max_entry_expiration
            ))
        } else if amount > 0 && expiration <= li.sequence_number {
            Err(err!(
                e,
                ContractError::AllowanceError,
                "expiration must be greater than ledger sequence: {} <= {}",
                expiration,
                li.sequence_number
            ))
        } else {
            Ok(li.sequence_number)
        }
    })?;

    if let Ok(allowance) = e.get_contract_data(key.try_into_val(e)?, StorageType::Temporary) {
        let mut updated_allowance: AllowanceValue = allowance.try_into_val(e)?;

        updated_allowance.amount = amount;
        let old_expiration = updated_allowance.expiration_ledger;
        updated_allowance.expiration_ledger = expiration;

        e.put_contract_data(
            key.try_into_val(e)?,
            updated_allowance.try_into_val(e)?,
            StorageType::Temporary,
            ().into(),
        )?;

        if old_expiration < expiration && amount > 0 {
            e.bump_contract_data(
                key.try_into_val(e)?,
                StorageType::Temporary,
                (expiration - ledger_seq).into(),
            )?;
        }
    } else if amount > 0 {
        //New allowance
        let val = AllowanceValue {
            amount,
            expiration_ledger: expiration,
        };
        e.put_contract_data(
            key.try_into_val(e)?,
            val.try_into_val(e)?,
            StorageType::Temporary,
            ().into(),
        )?;

        e.bump_contract_data(
            key.try_into_val(e)?,
            StorageType::Temporary,
            (expiration - ledger_seq).into(),
        )?;
    }

    Ok(())
}

// allowance is expected to exist
fn write_allowance_amount(
    e: &Host,
    from: Address,
    spender: Address,
    amount: i128,
) -> Result<(), HostError> {
    let key = DataKey::Allowance(AllowanceDataKey {
        from: from.clone(),
        spender: spender.clone(),
    });

    let allowance: AllowanceValue = e
        .get_contract_data(key.try_into_val(e)?, StorageType::Temporary)?
        .try_into_val(e)?;
    write_allowance(e, from, spender, amount, allowance.expiration_ledger)
}

// Metering: covered by components
pub fn spend_allowance(
    e: &Host,
    from: Address,
    spender: Address,
    amount: i128,
) -> Result<(), HostError> {
    let allowance = read_allowance(e, from.clone(), spender.clone())?;
    if allowance < amount {
        return Err(err!(
            e,
            ContractError::AllowanceError,
            "not enough allowance to spend: {} < {}",
            allowance,
            amount
        ));
    } else if amount > 0 {
        let new_allowance = allowance.checked_sub(amount).ok_or_else(|| {
            e.error(
                ContractError::OverflowError.into(),
                "allowance overflowed",
                &[],
            )
        })?;
        write_allowance_amount(e, from, spender, new_allowance)?;
    }
    Ok(())
}
