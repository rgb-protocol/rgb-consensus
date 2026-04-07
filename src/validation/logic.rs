// RGB Consensus Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Written in 2019-2024 by
//     Dr Maxim Orlovsky <orlovsky@lnp-bp.org>
//
// Copyright (C) 2019-2024 LNP/BP Standards Association. All rights reserved.
// Copyright (C) 2019-2024 Dr Maxim Orlovsky. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use std::cell::RefCell;
use std::collections::{BTreeMap, HashSet};
use std::rc::Rc;

use aluvm::data::Number;
use aluvm::isa::Instr;
use aluvm::reg::{Reg32, RegA};
use aluvm::Vm;
use amplify::confinement::Confined;
use amplify::Wrapper;
use strict_types::TypeSystem;

use super::validator::ValidationError;
use super::Failure;
use crate::schema::{AssignmentsSchema, GlobalSchema};
use crate::validation::Scripts;
use crate::vm::{ContractStateAccess, ContractStateEvolve, OpInfo, OrdOpRef, RgbIsa, VmContext};
use crate::{
    Assign, AssignmentType, Assignments, AssignmentsRef, ExposedSeal, ExposedState, Genesis,
    GlobalState, GlobalStateSchema, GlobalValues, MetaSchema, Metadata, OpId, Operation,
    OwnedStateSchema, RevealedState, Schema, SealClosingStrategy, Transition, TypedAssigns,
};

impl Schema {
    pub fn validate_state<'validator, S: ContractStateAccess + ContractStateEvolve>(
        &'validator self,
        consignment_types: &'validator TypeSystem,
        consignment_scripts: &'validator Scripts,
        genesis: &'validator Genesis,
        op: OrdOpRef,
        contract_state: Rc<RefCell<S>>,
        prev_state: &'validator BTreeMap<AssignmentType, Vec<RevealedState>>,
    ) -> Result<(), ValidationError> {
        let opid = op.id();

        let empty_assign_schema = AssignmentsSchema::default();
        let (metadata_schema, global_schema, owned_schema, assign_schema, validator, ty) = match op
        {
            OrdOpRef::Genesis(genesis) => {
                if genesis.seal_closing_strategy != SealClosingStrategy::FirstOpretOrTapret {
                    return Err(ValidationError::InvalidConsignment(
                        Failure::SchemaUnknownSealClosingStrategy(
                            opid,
                            genesis.seal_closing_strategy,
                        ),
                    ));
                }
                (
                    &self.genesis.metadata,
                    &self.genesis.globals,
                    &empty_assign_schema,
                    &self.genesis.assignments,
                    self.genesis.validator,
                    None::<u16>,
                )
            }
            OrdOpRef::Transition(
                Transition {
                    transition_type, ..
                },
                ..,
            ) => {
                let transition_schema = match self.transitions.get(transition_type) {
                    None => {
                        return Err(ValidationError::InvalidConsignment(
                            Failure::SchemaUnknownTransitionType(opid, *transition_type),
                        ));
                    }
                    Some(transition_details) => &transition_details.transition_schema,
                };

                (
                    &transition_schema.metadata,
                    &transition_schema.globals,
                    &transition_schema.inputs,
                    &transition_schema.assignments,
                    transition_schema.validator,
                    Some(transition_type.into_inner()),
                )
            }
        };

        self.validate_metadata(opid, op.metadata(), metadata_schema, consignment_types)?;
        self.validate_global_state(opid, op.globals(), global_schema, consignment_types)?;
        self.validate_prev_state(opid, prev_state, owned_schema)?;
        match op.assignments() {
            AssignmentsRef::Genesis(assignments) => {
                self.validate_new_state(opid, assignments, assign_schema, consignment_types)?
            }
            AssignmentsRef::Graph(assignments) => {
                self.validate_new_state(opid, assignments, assign_schema, consignment_types)?
            }
        };

        let op_info = OpInfo::with(opid, &op, prev_state);
        let context = VmContext {
            contract_id: genesis.contract_id(),
            op_info,
            contract_state,
        };

        // We need to run scripts as the very last step, since before that
        // we need to make sure that the operation data match the schema, so
        // scripts are not required to validate the structure of the state
        if let Some(validator) = validator {
            let scripts = consignment_scripts;
            let mut vm = Vm::<Instr<RgbIsa<S>>>::new();
            if let Some(ty) = ty {
                vm.registers.set_n(RegA::A16, Reg32::Reg0, ty);
            }
            if let Some(script) = scripts.get(&validator.lib) {
                let script_id = script.id();
                if script_id != validator.lib {
                    return Err(ValidationError::InvalidConsignment(Failure::ScriptIDMismatch(
                        opid,
                        validator.lib,
                        script_id,
                    )));
                }
            } else {
                return Err(ValidationError::InvalidConsignment(Failure::MissingScript(
                    opid,
                    validator.lib,
                )));
            }
            if !vm.exec(validator, |id| scripts.get(&id), &context) {
                let error_code: Option<Number> = vm.registers.get_n(RegA::A8, Reg32::Reg0).into();
                return Err(ValidationError::InvalidConsignment(Failure::ScriptFailure(
                    opid,
                    error_code.map(u8::from),
                    None,
                )));
            }
        }
        let contract_state = context.contract_state;
        if contract_state.borrow_mut().evolve_state(op).is_err() {
            return Err(ValidationError::InvalidConsignment(Failure::ContractStateFilled(opid)));
        }
        Ok(())
    }

    fn validate_metadata(
        &self,
        opid: OpId,
        metadata: &Metadata,
        metadata_schema: &MetaSchema,
        types: &TypeSystem,
    ) -> Result<(), ValidationError> {
        for type_id in metadata.keys().copied() {
            if !metadata_schema.as_unconfined().contains(&type_id) {
                return Err(ValidationError::InvalidConsignment(Failure::SchemaUnknownMetaType(
                    opid, type_id,
                )));
            }
        }

        for type_id in metadata_schema {
            let Some(value) = metadata.get(type_id) else {
                return Err(ValidationError::InvalidConsignment(Failure::SchemaNoMetadata(
                    opid, *type_id,
                )));
            };

            let sem_id = self
                .meta_types
                .get(type_id)
                .expect(
                    "if this metadata type were absent, the schema would not be able to pass the \
                     internal validation and we would not reach this point",
                )
                .sem_id;

            if types
                .strict_deserialize_type(sem_id, value.as_ref())
                .is_err()
            {
                return Err(ValidationError::InvalidConsignment(Failure::SchemaInvalidMetadata(
                    opid, sem_id,
                )));
            };
        }

        Ok(())
    }

    fn validate_global_state(
        &self,
        opid: OpId,
        global: &GlobalState,
        global_schema: &GlobalSchema,
        types: &TypeSystem,
    ) -> Result<(), ValidationError> {
        for field_id in global.keys() {
            if !global_schema.contains_key(field_id) {
                return Err(ValidationError::InvalidConsignment(
                    Failure::SchemaUnknownGlobalStateType(opid, *field_id),
                ));
            }
        }

        for (type_id, occ) in global_schema {
            let set = global
                .get(type_id)
                .cloned()
                .map(GlobalValues::into_inner)
                .map(Confined::release)
                .unwrap_or_default();

            let GlobalStateSchema { sem_id, max_items } = self
                .global_types
                .get(type_id)
                .expect(
                    "if the field were absent, the schema would not be able to pass the internal \
                     validation and we would not reach this point",
                )
                .global_state_schema;

            // Checking number of field occurrences
            let count = set.len() as u16;
            if let Err(err) = occ.check(count) {
                return Err(ValidationError::InvalidConsignment(
                    Failure::SchemaGlobalStateOccurrences(opid, *type_id, err),
                ));
            }
            if count as u32 > max_items.to_u32() {
                return Err(ValidationError::InvalidConsignment(Failure::SchemaGlobalStateLimit(
                    opid, *type_id, count, max_items,
                )));
            }

            // Validating data types
            for data in set {
                if types
                    .strict_deserialize_type(sem_id, data.as_ref())
                    .is_err()
                {
                    return Err(ValidationError::InvalidConsignment(
                        Failure::SchemaInvalidGlobalValue(opid, *type_id, sem_id),
                    ));
                };
            }
        }

        Ok(())
    }

    fn validate_prev_state(
        &self,
        id: OpId,
        prev_state: &BTreeMap<AssignmentType, Vec<RevealedState>>,
        assign_schema: &AssignmentsSchema,
    ) -> Result<(), ValidationError> {
        let type_ids = prev_state
            .keys()
            .chain(assign_schema.keys())
            .collect::<HashSet<_>>();
        for type_id in type_ids {
            let Some(schema_occurrences) = assign_schema.get(type_id) else {
                return Err(ValidationError::InvalidConsignment(
                    Failure::SchemaUnknownAssignmentType(id, *type_id),
                ));
            };
            let len = prev_state.get(type_id).map(|a| a.len() as u16).unwrap_or(0);
            if let Err(err) = schema_occurrences.check(len) {
                return Err(ValidationError::InvalidConsignment(Failure::SchemaInputOccurrences(
                    id, *type_id, err,
                )));
            }
        }

        Ok(())
    }

    fn validate_new_state<Seal: ExposedSeal>(
        &self,
        id: OpId,
        new_state: &Assignments<Seal>,
        assign_schema: &AssignmentsSchema,
        types: &TypeSystem,
    ) -> Result<(), ValidationError> {
        let type_ids = new_state
            .keys()
            .chain(assign_schema.keys())
            .collect::<HashSet<_>>();
        for type_id in type_ids {
            let Some(schema_occurrences) = assign_schema.get(type_id) else {
                return Err(ValidationError::InvalidConsignment(
                    Failure::SchemaUnknownAssignmentType(id, *type_id),
                ));
            };
            let len = new_state
                .get(type_id)
                .map(TypedAssigns::len_u16)
                .unwrap_or(0);
            if let Err(err) = schema_occurrences.check(len) {
                return Err(ValidationError::InvalidConsignment(
                    Failure::SchemaAssignmentOccurrences(id, *type_id, err),
                ));
            }
            let assignment = &self
                .owned_types
                .get(type_id)
                .expect(
                    "If the assignment were absent, the schema would not be able to pass the \
                     internal validation and we would not reach this point",
                )
                .owned_state_schema;
            match new_state.get(type_id) {
                None => Ok(()),
                Some(TypedAssigns::Declarative(set)) => set
                    .iter()
                    .try_for_each(|data| assignment.validate(id, *type_id, data, types)),
                Some(TypedAssigns::Fungible(set)) => set
                    .iter()
                    .try_for_each(|data| assignment.validate(id, *type_id, data, types)),
                Some(TypedAssigns::Structured(set)) => set
                    .iter()
                    .try_for_each(|data| assignment.validate(id, *type_id, data, types)),
            }?;
        }

        Ok(())
    }
}

impl OwnedStateSchema {
    pub fn validate<State: ExposedState, Seal: ExposedSeal>(
        &self,
        opid: OpId,
        state_type: AssignmentType,
        data: &Assign<State, Seal>,
        type_system: &TypeSystem,
    ) -> Result<(), ValidationError> {
        match data {
            Assign::Revealed { state, .. } | Assign::ConfidentialSeal { state, .. } => {
                match (self, state.state_data()) {
                    (OwnedStateSchema::Declarative, RevealedState::Void) => {}
                    (OwnedStateSchema::Fungible(schema), RevealedState::Fungible(v))
                        if v.as_inner().fungible_type() != *schema =>
                    {
                        return Err(ValidationError::InvalidConsignment(
                            Failure::FungibleTypeMismatch {
                                opid,
                                state_type,
                                expected: *schema,
                                found: v.as_inner().fungible_type(),
                            },
                        ));
                    }
                    (OwnedStateSchema::Fungible(_), RevealedState::Fungible(_)) => {}
                    (OwnedStateSchema::Structured(sem_id), RevealedState::Structured(data)) => {
                        if type_system
                            .strict_deserialize_type(*sem_id, data.as_ref())
                            .is_err()
                        {
                            return Err(ValidationError::InvalidConsignment(
                                Failure::SchemaInvalidOwnedValue(opid, state_type, *sem_id),
                            ));
                        };
                    }
                    // all other options are mismatches
                    (state_schema, found) => {
                        return Err(ValidationError::InvalidConsignment(
                            Failure::StateTypeMismatch {
                                opid,
                                state_type,
                                expected: state_schema.state_type(),
                                found: found.state_type(),
                            },
                        ));
                    }
                }
            }
        }
        Ok(())
    }
}
