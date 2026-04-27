// Package scoring implements Milestone 2 of the Titus finding-scoring design:
// declarative, static-only modifiers applied at finding-creation time.
//
// A [Condition] is the v1 DSL leaf. It is evaluated against the primary match
// for a finding (the first *types.Match in the slice passed to the engine).
// Three leaf implementations ship in M2:
//
//   - matchGroupCondition              — regex test against a named capture group
//   - surroundingContextContainsCondition — substring test against Snippet.Before+After
//   - matchLengthCondition             — integer comparison of len(Snippet.Matching)
//
// Compound conditions (all/any/not), HTTP conditions, and custom Go scorers
// are out of scope for M2 (see finding-scoring-design.md §Milestones).
package scoring
