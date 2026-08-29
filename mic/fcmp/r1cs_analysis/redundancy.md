# Does the FCMP++ constraint system carry any redundant rows?

`redundancy.py` answers it on the R1CS circuit that a real `Fcmp.prove` builds, at every tree depth from 1 to 8, on both curves. From the repository root:

```bash
python -m mic.fcmp.r1cs_analysis.redundancy                # the sweep, ~31 s
python -m mic.fcmp.r1cs_analysis.redundancy --layers 4     # one depth, ~4 s
```

## The question

A row is redundant when the system would have the same solution even without it.
Redundant rows are wasted verifier work at best and a modelling mistake at worst.

Precisely:

> Row `r` is **redundant** when every solution of the other rows satisfies `r`
> anyway, so that deleting `r` leaves the solution set unchanged.

Redundancy is therefore a property of the
coefficient matrix and nothing else: no witness, no sampled input and no
commitment values enter the definition, so a verdict read off it holds for every
input at once.

The circuits have exactly two row shapes:

```
linear   <A, w> = 0                        an ordinary linear equation
mul      w[aL_i] . w[aR_i] = w[aO_i]       single columns 
```

For the linear block the question is decided exactly, by using the rank. A block of `n`
linear rows with rank `n` has no row in the span of the others, so nothing is
removable. Rank short of `n` means some row is a combination of the rest and
constrains nothing the others didn't do already.

## The theorem

Call a column **unique** when exactly one linear row uses it.

> **Theorem.** A linear row with a unique column cannot be written as a
> combination of the other linear rows.
>
> *Proof.* Let row `r` have unique column `c`, so `r[c] != 0` while `r_i[c] = 0`
> for every other linear row `r_i`. Suppose `r = sum_i lambda_i . r_i` and compare
> the two sides at column `c`. On the right every term is `lambda_i . 0`, so the
> right side is `0`. On the left the value is `r[c]`, which is not `0`. That is a
> contradiction, so no such combination exists. ∎

> **Corollary.** If every linear row has a unique column, the linear rows are
> linearly independent. The linear block then has full row rank, and no linear row
> is implied by the other linear rows.

Note what the corollary is about. It talks about the linear rows only, and the
circuit is more than its linear rows, it has mul rows.

## The limit of the corollary for the R1CS circuit

Redundancy in the *full* R1CS means every solution of the other rows satisfies
this one, and the other rows include the mul rows. The corollary says nothing
about those, so full rank does not settle the full question. 

So the honest form of the claim is:

> Full rank rules out a linear row being implied **by the other linear rows**. It
> does not rule out a linear row being implied by the mul rows.

## The results

`python -m mic.fcmp.r1cs_analysis.redundancy`

| layers | circuit | rows | linear | rank | implied | own a unique column | mul | mul sharing |
|---|---|---|---|---|---|---|---|---|
| 1 | C1 | 313 | 216 | 216 | **0** | 216/216 | 97 | 0 |
| 1 | C2 | no rows at this depth | | | | | | |
| 2 | C1 | 313 | 216 | 216 | **0** | 216/216 | 97 | 0 |
| 2 | C2 | 100 | 68 | 68 | **0** | 68/68 | 32 | 0 |
| 3 | C1 | 473 | 324 | 324 | **0** | 324/324 | 149 | 0 |
| 3 | C2 | 100 | 68 | 68 | **0** | 68/68 | 32 | 0 |
| 4 | C1 | 473 | 324 | 324 | **0** | 324/324 | 149 | 0 |
| 4 | C2 | 200 | 136 | 136 | **0** | 136/136 | 64 | 0 |
| 5 | C1 | 633 | 432 | 432 | **0** | 432/432 | 201 | 0 |
| 5 | C2 | 200 | 136 | 136 | **0** | 136/136 | 64 | 0 |
| 6 | C1 | 633 | 432 | 432 | **0** | 432/432 | 201 | 0 |
| 6 | C2 | 300 | 204 | 204 | **0** | 204/204 | 96 | 0 |
| 7 | C1 | 793 | 540 | 540 | **0** | 540/540 | 253 | 0 |
| 7 | C2 | 300 | 204 | 204 | **0** | 204/204 | 96 | 0 |
| 8 | C1 | 793 | 540 | 540 | **0** | 540/540 | 253 | 0 |
| 8 | C2 | 400 | 272 | 272 | **0** | 272/272 | 128 | 0 |

4112 linear rows across 15 circuits. Full rank in every one. Every linear row has
a unique column in every one. No two mul rows share a column in any of them.

The proportions stay flat as the tree grows rather than drifting, C1 going from
216 linear against 97 mul at one layer to 540 against 253 at eight, with the
unique column count tracking the linear count exactly. Nothing accumulates, which
is what you would expect if the unique column is created by construction rather
than surviving by chance.

The depths pair up because the tree alternates curves, so C1 changes at odd depths
and C2 at even. Layers 1 and 2 give the same C1, 3 and 4 the same, and so on.

## The verdict

> **NOT REDUNDANT.** No linear row in either circuit, at any depth from 1 to 8,
> lies in the span of the other linear rows. That is proved by analyzing the
> rank. 

So it is not possible to reduce the circuit or remove some operations to have it
faster. At least not from the linear rows.

## What this does not establish

- **Full rank is not correctness.** It says only no row is wasted. It says nothing
  about whether the rows encode the intended statement. 
- **A missing constraint is invisible.** Rank sees only the rows that are there.
  The gap where a constraint should have been has no rank to be missing. 