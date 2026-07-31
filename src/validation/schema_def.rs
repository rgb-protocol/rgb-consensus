// RGB Consensus Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2026 RGB-Tools developers. All rights reserved.
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

use std::collections::BTreeSet;
use std::str::FromStr;

use aluvm::library::LibId;
use amplify::confinement::ConfinedOrdMap;
use armor::{ArmorHeader, AsciiArmor, StrictArmor};
use strict_encoding::{StrictDeserialize, StrictSerialize};
use strict_types::typesys::{Error as TypeSystemError, UnknownType};
use strict_types::{SystemBuilder, TypeLib, TypeLibId, TypeSystem};

use crate::validation::{Scripts, ValidationError};
use crate::{Schema, SchemaId, LIB_NAME_RGB_LOGIC};

const ASCII_ARMOR_NAME: &str = "Name";
const ASCII_ARMOR_SCRIPT: &str = "Alu-Lib";
const ASCII_ARMOR_TYPE_LIB: &str = "Type-Lib";

/// Maximum number of strict type libraries a schema definition may carry.
pub const SCHEMA_MAX_TYPE_LIBS: usize = 0xFF;

/// The strict type libraries a [`SchemaDefinition`] carries, keyed by their id.
pub type TypeLibs = ConfinedOrdMap<TypeLibId, TypeLib, 0, SCHEMA_MAX_TYPE_LIBS>;

/// Error verifying a [`SchemaDefinition`] into [`SchemaRules`].
#[derive(Clone, Eq, PartialEq, Debug, Display, Error, From)]
#[display(doc_comments)]
pub enum SchemaDefError {
    /// type library is keyed by {0}, but its content commits to {1}.
    TypeLibIdMismatch(TypeLibId, TypeLibId),

    /// AluVM library is keyed by {0}, but its content commits to {1}.
    ScriptIdMismatch(LibId, LibId),

    /// the AluVM library {0}, required by the schema, is missing.
    ScriptAbsent(LibId),

    /// the AluVM library {0} is not reachable from the schema.
    ScriptExtraneous(LibId),

    /// the type library {0} is not needed by the schema.
    TypeLibExtraneous(TypeLibId),

    /// the type libraries do not form a complete type system. {0}
    IncompleteTypeLibs(String),

    /// the type libraries do not define a type the schema commits to. {0}
    #[from]
    TypeAbsent(UnknownType),

    /// {0}
    #[from]
    Schema(ValidationError),
}

impl From<Vec<TypeSystemError>> for SchemaDefError {
    fn from(errors: Vec<TypeSystemError>) -> Self {
        Self::IncompleteTypeLibs(
            errors
                .iter()
                .map(TypeSystemError::to_string)
                .collect::<Vec<_>>()
                .join("; "),
        )
    }
}

impl From<TypeSystemError> for SchemaDefError {
    fn from(err: TypeSystemError) -> Self { Self::IncompleteTypeLibs(err.to_string()) }
}

/// The serialized form of the contract rules: schema, strict type libraries and
/// AluVM libraries.
///
/// This is what an SDF file contains and what crosses a trust boundary. It is
/// *not* usable for validation: [`SchemaDefinition::verify`] turns it into
/// [`SchemaRules`], which is the only form the validator accepts.
///
/// The type system is never serialized. It is rebuilt from `libs` by
/// [`SystemBuilder`], which computes every [`strict_types::SemId`] from the
/// library contents rather than taking the sender's word for it; the schema
/// then authenticates those definitions through the ids it already commits to.
#[derive(Clone, Eq, PartialEq, Debug, Display)]
#[display(AsciiArmor::to_ascii_armored_string)]
#[derive(StrictType, StrictDumb, StrictEncode, StrictDecode)]
#[strict_type(lib = LIB_NAME_RGB_LOGIC)]
#[cfg_attr(
    feature = "serde",
    derive(Serialize, Deserialize),
    serde(crate = "serde_crate", rename_all = "camelCase")
)]
pub struct SchemaDefinition {
    pub schema: Schema,

    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    pub libs: TypeLibs,

    #[cfg_attr(feature = "serde", serde(with = "strict_encoding::serde_helpers::confined"))]
    pub scripts: Scripts,
}

impl StrictSerialize for SchemaDefinition {}
impl StrictDeserialize for SchemaDefinition {}

impl SchemaDefinition {
    pub fn new(schema: Schema, libs: TypeLibs, scripts: Scripts) -> Self {
        Self {
            schema,
            libs,
            scripts,
        }
    }

    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.schema.schema_id() }

    /// Rebuilds the type system from the type libraries and checks the schema
    /// against it, yielding the verified form.
    ///
    /// Nothing supplied by the sender is taken at face value: every library is
    /// re-keyed by its own commitment, every [`strict_types::SemId`] is
    /// recomputed by [`SystemBuilder`] from the library contents, and the
    /// resulting system must define every type the schema commits to.
    ///
    /// The definition must also carry no type library the schema cannot reach.
    /// That check is per-library, not per-type: a library defining at least one
    /// type the schema commits to is accepted whole, unused types included, so
    /// the same schema admits definitions of very different sizes. Bound the
    /// size of a definition before verifying one from an untrusted peer.
    pub fn verify(&self) -> Result<SchemaRules, SchemaDefError> {
        for (id, lib) in &self.libs {
            let actual = lib.id();
            if actual != *id {
                return Err(SchemaDefError::TypeLibIdMismatch(*id, actual));
            }
        }
        let types = self.derive_types()?;
        self.check_libs_needed(&types)?;
        SchemaRules::with(self.schema.clone(), types, self.scripts.clone())
    }

    fn derive_types(&self) -> Result<TypeSystem, SchemaDefError> {
        let mut builder = SystemBuilder::new();
        for lib in self.libs.values() {
            builder = builder.import(lib.clone())?;
        }
        let sys = builder.finalize()?;
        // keeps only what the schema commits to, and fails if any of it is absent
        Ok(sys.as_types().extract(self.schema.types())?)
    }

    /// Rejects type libraries the schema has no use for at all.
    ///
    /// This bounds neither the size of a definition nor its contents beyond
    /// that: a library is kept as it comes as soon as it defines a single type
    /// the schema commits to.
    ///
    /// A library is needed if it defines one of the types the schema commits
    /// to, or if a needed library depends on it: the latter are not visible in
    /// the derived type system, yet [`SystemBuilder::finalize`] requires them
    /// to be present, so the needed set has to be closed over dependencies
    /// rather than read off the types alone.
    fn check_libs_needed(&self, types: &TypeSystem) -> Result<(), SchemaDefError> {
        let mut queue = Vec::new();
        for (id, lib) in &self.libs {
            let (_, defines) = lib.to_dependency_types();
            if defines.iter().any(|sem_id| types.contains_key(sem_id)) {
                queue.push(*id);
            }
        }

        let mut needed = BTreeSet::new();
        while let Some(id) = queue.pop() {
            if !needed.insert(id) {
                continue;
            }
            // an absent dependency has already been reported by `derive_types`
            if let Some(lib) = self.libs.get(&id) {
                queue.extend(lib.dependencies.iter().map(|dep| dep.id));
            }
        }

        match self.libs.keys().find(|id| !needed.contains(*id)) {
            Some(id) => Err(SchemaDefError::TypeLibExtraneous(*id)),
            None => Ok(()),
        }
    }
}

impl StrictArmor for SchemaDefinition {
    type Id = SchemaId;
    const PLATE_TITLE: &'static str = "RGB SCHEMA DEFINITION";

    fn armor_id(&self) -> Self::Id { self.schema_id() }
    fn armor_headers(&self) -> Vec<ArmorHeader> {
        let mut headers = vec![ArmorHeader::new(ASCII_ARMOR_NAME, self.schema.name.to_string())];
        for lib in self.libs.values() {
            headers.push(ArmorHeader::new(ASCII_ARMOR_TYPE_LIB, lib.name.to_string()));
        }
        for id in self.scripts.keys() {
            headers.push(ArmorHeader::new(ASCII_ARMOR_SCRIPT, id.to_string()));
        }
        headers
    }
}

impl FromStr for SchemaDefinition {
    type Err = armor::StrictArmorError;
    fn from_str(s: &str) -> Result<Self, Self::Err> { Self::from_ascii_armored_str(s) }
}

/// The verified contract rules: schema, type system and AluVM libraries.
///
/// This is the *trusted* side of validation. A value of this type cannot be
/// built without the schema having been checked against the type system and the
/// AluVM libraries it reaches, so the validator does not have to trust its
/// input. It is deliberately not serializable: it can only be obtained from
/// [`SchemaDefinition::verify`] or built locally from code.
#[derive(Clone, Eq, PartialEq, Debug)]
pub struct SchemaRules {
    schema: Schema,
    types: TypeSystem,
    scripts: Scripts,
}

impl SchemaRules {
    /// Checks a schema against a locally-obtained type system and AluVM
    /// libraries.
    ///
    /// The AluVM libraries are re-keyed by their own commitment and must be
    /// exactly the closure the schema reaches. The type system is not
    /// re-derived, and this is a property of the data rather than a judgement
    /// about the source: a [`LibId`] is recomputable from the library it keys,
    /// while a [`TypeSystem`] maps a [`strict_types::SemId`] to a type whose
    /// name it does not carry, and the name is part of what the id commits to.
    /// It must therefore come from a trusted local source - a [`SystemBuilder`]
    /// over known type libraries, which derives every id itself. For anything
    /// that crossed a trust boundary use [`SchemaDefinition::verify`], which
    /// does that derivation as part of the check.
    ///
    /// The library checks are not a defence against a tampered local store: a
    /// tampered type system would be just as fatal and cannot be caught here.
    /// They fail fast, and blame the schema, when the separately stored parts
    /// are put back together inconsistently - without them the same defect
    /// surfaces mid-validation as a failure of the consignment being validated.
    pub fn with(
        schema: Schema,
        trusted_types: TypeSystem,
        scripts: Scripts,
    ) -> Result<Self, SchemaDefError> {
        for (id, lib) in &scripts {
            let actual = lib.id();
            if actual != *id {
                return Err(SchemaDefError::ScriptIdMismatch(*id, actual));
            }
        }
        // The schema commits to the validators it enters an AluVM library at,
        // but a library may call into others, so the set of libraries a schema
        // really needs is the closure of those calls - not just the entry
        // points. Anything outside that closure is dead weight and rejected.
        let mut reachable = BTreeSet::new();
        let mut queue = schema.libs().collect::<Vec<_>>();
        while let Some(id) = queue.pop() {
            if !reachable.insert(id) {
                continue;
            }
            let lib = scripts.get(&id).ok_or(SchemaDefError::ScriptAbsent(id))?;
            queue.extend(lib.libs.iter().copied());
        }
        if let Some(id) = scripts.keys().find(|id| !reachable.contains(*id)) {
            return Err(SchemaDefError::ScriptExtraneous(*id));
        }

        schema.verify(&trusted_types)?;
        Ok(Self {
            schema,
            types: trusted_types,
            scripts,
        })
    }

    #[inline]
    pub fn schema(&self) -> &Schema { &self.schema }

    #[inline]
    pub fn types(&self) -> &TypeSystem { &self.types }

    #[inline]
    pub fn scripts(&self) -> &Scripts { &self.scripts }

    #[inline]
    pub fn schema_id(&self) -> SchemaId { self.schema.schema_id() }

    /// The same rules with a different schema, re-checked against the same type
    /// system and AluVM libraries.
    pub fn with_schema(&self, schema: Schema) -> Result<Self, SchemaDefError> {
        Self::with(schema, self.types.clone(), self.scripts.clone())
    }

    /// The same rules with different AluVM libraries, re-checked against the
    /// same schema and type system.
    pub fn with_scripts(&self, scripts: Scripts) -> Result<Self, SchemaDefError> {
        Self::with(self.schema.clone(), self.types.clone(), scripts)
    }

    /// Decomposes the rules into their parts.
    pub fn into_parts(self) -> (Schema, TypeSystem, Scripts) {
        (self.schema, self.types, self.scripts)
    }
}

#[cfg(test)]
mod test {
    use strict_encoding::StrictDumb;

    use super::*;

    #[test]
    fn armored_str_round_trip() {
        let schema_def = SchemaDefinition::strict_dumb();
        let armored = schema_def.to_string();
        assert_eq!(
            SchemaDefinition::from_str(&armored).expect("armored schema definition"),
            schema_def
        );
    }

    #[test]
    fn armored_str_wrong_id() {
        let schema_def = SchemaDefinition::strict_dumb();
        let armored = schema_def.to_string().replace(
            &schema_def.schema_id().to_string(),
            &SchemaId::from_array([0xADu8; 32]).to_string(),
        );
        assert!(SchemaDefinition::from_str(&armored).is_err());
    }

    #[test]
    fn type_lib_id_is_rederived() {
        let mut schema_def = SchemaDefinition::strict_dumb();
        let lib = TypeLib::strict_dumb();
        schema_def
            .libs
            .insert(TypeLibId::from([0xADu8; 32]), lib.clone())
            .unwrap();
        assert_eq!(
            schema_def.verify(),
            Err(SchemaDefError::TypeLibIdMismatch(TypeLibId::from([0xADu8; 32]), lib.id()))
        );
    }
}
