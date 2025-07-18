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

use strict_types::TypeSystem;

use crate::{validation, OpFullType, OpSchema, OwnedStateSchema, Schema};

impl Schema {
    pub fn verify(&self, types: &TypeSystem) -> validation::Status {
        let mut status = validation::Status::new();

        status += self.verify_operation(OpFullType::Genesis, &self.genesis);
        for (type_id, transition_details) in &self.transitions {
            status += self.verify_operation(
                OpFullType::StateTransition(*type_id),
                &transition_details.transition_schema,
            );
        }

        for (type_id, meta_details) in &self.meta_types {
            if !types.contains_key(&meta_details.sem_id) {
                status.add_failure(validation::Failure::SchemaMetaSemIdUnknown(
                    *type_id,
                    meta_details.sem_id,
                ));
            }
        }

        for (type_id, global_details) in &self.global_types {
            if !types.contains_key(&global_details.global_state_schema.sem_id) {
                status.add_failure(validation::Failure::SchemaGlobalSemIdUnknown(
                    *type_id,
                    global_details.global_state_schema.sem_id,
                ));
            }
        }

        for (type_id, assignment_details) in &self.owned_types {
            if let OwnedStateSchema::Structured(sem_id) = &assignment_details.owned_state_schema {
                if !types.contains_key(sem_id) {
                    status.add_failure(validation::Failure::SchemaOwnedSemIdUnknown(
                        *type_id, *sem_id,
                    ));
                }
            }
        }

        status
    }

    fn verify_operation(&self, op_type: OpFullType, schema: &impl OpSchema) -> validation::Status {
        let mut status = validation::Status::new();

        for type_id in schema.metadata() {
            if !self.meta_types.contains_key(type_id) {
                status.add_failure(validation::Failure::SchemaOpMetaTypeUnknown(op_type, *type_id));
            }
        }
        if matches!(schema.inputs(), Some(inputs) if inputs.is_empty()) {
            status.add_failure(validation::Failure::SchemaOpEmptyInputs(op_type));
        }
        for type_id in schema.globals().keys() {
            if !self.global_types.contains_key(type_id) {
                status
                    .add_failure(validation::Failure::SchemaOpGlobalTypeUnknown(op_type, *type_id));
            }
        }
        for type_id in schema.assignments().keys() {
            if !self.owned_types.contains_key(type_id) {
                status.add_failure(validation::Failure::SchemaOpAssignmentTypeUnknown(
                    op_type, *type_id,
                ));
            }
        }

        status
    }
}
