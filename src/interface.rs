use crate::{IdlDocument, IdlError, IdlInterface, InterfaceKind, WitnessField, };

impl WitnessField {
    pub fn structural_type(&self) -> &str {
        self.wire_type
            .as_deref()
            .unwrap_or(self.type_.as_str())
    }
}

impl IdlDocument {
    pub fn lock_witness(&self) -> Result<&IdlInterface, IdlError> {
        if self.idl_version != "0.1.0" {
            return Err(IdlError::UnsupportedVersion { version: self.idl_version.clone(), });
        }

        let mut matches = self.interfaces.iter().filter(|interface| {
            interface.kind == InterfaceKind::WitnessArgsLock
        });

        let interface = matches
            .next()
            .ok_or(IdlError::MissingLockWitnessInterface)?;

        if matches.next().is_some() {
            return Err(IdlError::DuplicateLockWitnessInterface);
        }

        if interface.encoding.id != "ckb-idl-linear-0.1.0" {
            return Err(IdlError::UnsupportedEncoding { encoding: interface.encoding.id.clone(), });
        }

        Ok(interface)
    }
}