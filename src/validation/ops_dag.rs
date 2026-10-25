// RGB Consensus Library: consensus layer for RGB smart contracts.
//
// SPDX-License-Identifier: Apache-2.0
//
// Copyright (C) 2025 RGB-Tools developers
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

use std::collections::HashMap;

use daggy::{Dag, NodeIndex, Walker};

use crate::{AssignmentType, OpId, Opout, Transition};

/// Operations graph: one node per operation, one edge per spent opout, going from
/// the operation that created the opout to the one spending it and labelled with
/// the opout's assignment type and number.
type OpsGraph = Dag<OpId, (AssignmentType, u16)>;

/// Index to store operation-node relations
type OpIndex = HashMap<OpId, NodeIndex>;

/// DAG representing the RGB operations graph.
///
/// Its size is linear in the number of operations and spent opouts. Unspent
/// opouts are not represented: they belong to the node of the operation creating
/// them, so walking up from one starts from [`Self::op_node`] of its `op`.
#[derive(Clone, Debug, Default)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize), serde(crate = "serde_crate"))]
pub struct OpsDag {
    dag: OpsGraph,
    index: OpIndex,
}

impl OpsDag {
    pub fn new() -> Self { Self::default() }

    /// Returns the node of the given operation, creating it if missing.
    pub fn register_op(&mut self, opid: OpId) -> NodeIndex {
        *self
            .index
            .entry(opid)
            .or_insert_with(|| self.dag.add_node(opid))
    }

    /// Records that the operation `opid` spends `input`.
    ///
    /// Both operation nodes are created if missing, so inputs can be connected in
    /// any order. Each input must be connected once: connecting it again adds a
    /// parallel edge.
    pub fn connect_input(&mut self, input: Opout, opid: OpId) {
        let src = self.register_op(input.op);
        let dst = self.register_op(opid);
        let _ = self.dag.add_edge(src, dst, (input.ty, input.no));
    }

    /// Records that the operation `opid` spends all the inputs of `transition`.
    ///
    /// `opid` must be `transition.id()`; it is taken to avoid hashing the transition again, and
    /// is not checked. Each transition must be connected once.
    pub fn connect_transition(&mut self, transition: &Transition, opid: OpId) {
        self.register_op(opid);
        for input in &transition.inputs {
            self.connect_input(input, opid);
        }
    }

    /// The number of operations in the DAG.
    pub fn node_count(&self) -> usize { self.dag.node_count() }

    /// The number of spent opouts in the DAG.
    pub fn edge_count(&self) -> usize { self.dag.edge_count() }

    /// The node of the given operation, if it is in the DAG.
    pub fn op_node(&self, opid: &OpId) -> Option<NodeIndex> { self.index.get(opid).copied() }

    /// The operation at `node`.
    ///
    /// **Panics** if `node` is not a node of this DAG.
    pub fn opid(&self, node: NodeIndex) -> OpId { self.dag[node] }

    /// The opouts spent by the operation at `node`, each with the node of the
    /// operation that created it.
    pub fn spent_opouts(&self, node: NodeIndex) -> impl Iterator<Item = (Opout, NodeIndex)> + '_ {
        self.dag
            .parents(node)
            .iter(&self.dag)
            .map(move |(edge, parent)| {
                let (ty, no) = self.dag[edge];
                (Opout::new(self.dag[parent], ty, no), parent)
            })
    }
}

#[cfg(test)]
mod test {
    use std::collections::HashSet;

    use amplify::confinement::NonEmptyOrdSet;

    use super::*;
    use crate::strict_encoding::StrictDumb;
    use crate::Inputs;

    const A: AssignmentType = AssignmentType::with(4000);

    fn op(n: u8) -> OpId { OpId::from([n; 32]) }

    /// Depth-first walk from `from` to its ancestors, returning each visited
    /// operation once, in visit order.
    fn ancestors(dag: &OpsDag, from: OpId) -> Vec<OpId> {
        let mut stack = vec![dag.op_node(&from).unwrap()];
        let mut visited = HashSet::new();
        let mut order = vec![];
        while let Some(node) = stack.pop() {
            if !visited.insert(node) {
                continue;
            }
            order.push(dag.opid(node));
            for (_, parent) in dag.spent_opouts(node) {
                if !visited.contains(&parent) {
                    stack.push(parent);
                }
            }
        }
        order
    }

    fn set(ops: impl IntoIterator<Item = OpId>) -> HashSet<OpId> { ops.into_iter().collect() }

    /// The inputs of the reference graph:
    /// G -(A,0)-> T1, G -(A,1)-> T2, T1 -(A,1)-> T2, T2 -(A,0)-> T3, T1 -(A,0)-> T3
    fn reference_inputs() -> Vec<(Opout, OpId)> {
        let (g, t1, t2, t3) = (op(0), op(1), op(2), op(3));
        vec![
            (Opout::new(g, A, 0), t1),
            (Opout::new(g, A, 1), t2),
            (Opout::new(t1, A, 1), t2),
            (Opout::new(t2, A, 0), t3),
            (Opout::new(t1, A, 0), t3),
        ]
    }

    fn build(inputs: &[(Opout, OpId)]) -> OpsDag {
        let mut dag = OpsDag::new();
        dag.register_op(op(0));
        for (input, opid) in inputs {
            dag.connect_input(*input, *opid);
        }
        dag
    }

    #[test]
    fn walk_leaf_to_genesis() {
        let inputs = reference_inputs();
        let dag = build(&inputs);
        assert_eq!(dag.node_count(), 4);
        assert_eq!(dag.edge_count(), 5);

        let visited = ancestors(&dag, op(3));
        // T1 is reachable through two paths but visited once
        assert_eq!(visited.len(), 4);
        assert_eq!(set(visited), set([op(0), op(1), op(2), op(3)]));

        let genesis = dag.op_node(&op(0)).unwrap();
        assert_eq!(dag.spent_opouts(genesis).count(), 0);

        // every opout met along the walk is an input that was connected, with the
        // node of its creating operation
        let mut met = HashSet::new();
        for (_, opid) in &inputs {
            for (opout, parent) in dag.spent_opouts(dag.op_node(opid).unwrap()) {
                assert_eq!(dag.opid(parent), opout.op);
                assert!(inputs.contains(&(opout, *opid)));
                met.insert(opout);
            }
        }
        assert_eq!(met.len(), inputs.len());
    }

    #[test]
    fn walk_from_genesis() {
        let dag = build(&reference_inputs());
        assert_eq!(ancestors(&dag, op(0)), vec![op(0)]);
    }

    #[test]
    fn walk_from_inner_node() {
        let dag = build(&reference_inputs());
        assert_eq!(set(ancestors(&dag, op(1))), set([op(0), op(1)]));
        assert_eq!(set(ancestors(&dag, op(2))), set([op(0), op(1), op(2)]));
    }

    #[test]
    fn walk_down_from_genesis() {
        let dag = build(&reference_inputs());
        // spender of each opout, built by inverting the spent opouts
        let mut spender = HashMap::new();
        for node in dag.dag.graph().node_indices() {
            for (opout, _) in dag.spent_opouts(node) {
                assert!(spender.insert(opout, dag.opid(node)).is_none());
            }
        }
        let mut stack = vec![op(0)];
        let mut reached = HashSet::new();
        while let Some(opid) = stack.pop() {
            for (input, expected) in reference_inputs() {
                if input.op != opid {
                    continue;
                }
                assert_eq!(spender[&input], expected);
                if reached.insert(expected) {
                    stack.push(expected);
                }
            }
        }
        assert_eq!(reached, set([op(1), op(2), op(3)]));

        // unspent outputs are not spent by anyone
        assert!(!spender.contains_key(&Opout::new(op(3), A, 0)));
    }

    #[test]
    fn walk_wide_transition() {
        let (g, t) = (op(0), op(1));
        let mut dag = OpsDag::new();
        for no in 0..50 {
            dag.connect_input(Opout::new(g, A, no), t);
        }
        assert_eq!(dag.node_count(), 2);
        assert_eq!(dag.edge_count(), 50);

        let spent = dag
            .spent_opouts(dag.op_node(&t).unwrap())
            .map(|(opout, _)| opout)
            .collect::<HashSet<_>>();
        assert_eq!(spent.len(), 50);
        assert!(spent.iter().all(|opout| opout.op == g));

        // G is visited once despite the 50 parallel edges
        let visited = ancestors(&dag, t);
        assert_eq!(visited, vec![t, g]);
    }

    #[test]
    fn walk_long_chain() {
        let len = 10_000u32;
        let chain_op = |n: u32| {
            let mut id = [0u8; 32];
            id[..4].copy_from_slice(&n.to_le_bytes());
            OpId::from(id)
        };
        let mut dag = OpsDag::new();
        for n in 1..=len {
            dag.connect_input(Opout::new(chain_op(n - 1), A, 0), chain_op(n));
        }
        assert_eq!(dag.node_count(), len as usize + 1);
        assert_eq!(dag.edge_count(), len as usize);

        let visited = ancestors(&dag, chain_op(len));
        assert_eq!(visited.len(), len as usize + 1);
        assert_eq!(visited.last(), Some(&chain_op(0)));
    }

    #[test]
    fn walk_after_out_of_order_build() {
        let inputs = reference_inputs();
        let forward = build(&inputs);
        let mut reversed = inputs.clone();
        reversed.reverse();
        let backward = build(&reversed);

        assert_eq!(backward.node_count(), forward.node_count());
        assert_eq!(backward.edge_count(), forward.edge_count());
        assert_eq!(set(ancestors(&backward, op(3))), set(ancestors(&forward, op(3))));
        for (input, opid) in &inputs {
            let spent = backward
                .spent_opouts(backward.op_node(opid).unwrap())
                .map(|(opout, _)| opout)
                .collect::<HashSet<_>>();
            assert!(spent.contains(input));
        }
    }

    #[test]
    fn connect_transition_matches_connect_input() {
        let inputs = reference_inputs();
        let incremental = build(&inputs);
        let mut by_transition = OpsDag::new();
        for (opid, group) in [(op(1), vec![0]), (op(2), vec![1, 2]), (op(3), vec![3, 4])] {
            let mut transition = Transition::strict_dumb();
            transition.inputs = Inputs::from(NonEmptyOrdSet::from_iter_checked(
                group.into_iter().map(|i| inputs[i].0),
            ));
            by_transition.connect_transition(&transition, opid);
        }
        assert_eq!(by_transition.node_count(), incremental.node_count());
        assert_eq!(by_transition.edge_count(), incremental.edge_count());
        for opid in [op(1), op(2), op(3)] {
            let spent = |dag: &OpsDag| {
                dag.spent_opouts(dag.op_node(&opid).unwrap())
                    .map(|(opout, _)| opout)
                    .collect::<HashSet<_>>()
            };
            assert_eq!(spent(&by_transition), spent(&incremental));
        }
    }
}
