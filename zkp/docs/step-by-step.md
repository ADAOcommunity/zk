## Step by Step overview of protocols included here:
All we really care about in this library is Verification - we assume setup & proof generation will be done offchain. However, we include the other sections here for context.

- [Groth16](#groth16)
  - [Setup](#1-setup-trusted-parameter-generation)
  - [Proof Generation](#2-proof-generation-provers-side)
  - [Verification](#3-verification-verifiers-side)
- [PLONK](#plonk)
  - [Setup](#1-setup-trusted-parameter-generation-1)
  - [Proof Generation](#2-proof-generation-provers-side-1)
  - [Verification](#3-verification-verifiers-side-1)
- [Bulletproofs](#bulletproofs)
  - [Setup](#1-setup-public-parameters-generation)
  - [Proof Generation](#2-proof-generation-provers-side-2)
  - [Verification](#3-verification-verifiers-side-2)

# **Groth16**

## **1. Setup (Trusted Parameter Generation)**
The setup phase generates public parameters needed for proof generation and verification.

### **Step 1: Define the arithmetic circuit**
- Construct a Rank-1 Constraint System (R1CS) for the function \( f(x) \) to be proven.
- The circuit enforces constraints of the form:
  \[
  A(w) ⋅ B(w) = C(w)
  \]
  where \( w \) represents witness variables.

### **Step 2: Compute the Quadratic Arithmetic Program (QAP)**
- Convert the R1CS into a QAP representation.
- Define polynomials \( A(x), B(x), C(x) \) corresponding to the constraints.

### **Step 3: Perform a trusted setup**
- A trusted authority generates the Structured Reference String (SRS):
  - **Proving key (PK):** Used to generate proofs.
  - **Verification key (VK):** Used to verify proofs.
- This involves selecting a secret scalar \( τ \) and computing:
  \[
  g^τ, g^{τ^2}, \dots, g^{τ^d}
  \]
  in an elliptic curve group.

- The secret \( τ \) is discarded after setup to maintain security.

---

## **2. Proof Generation (Prover's Side)**
The prover constructs a zk-SNARK proof for a statement \( x \) using a witness \( w \).

### **Step 1: Compute witness values**
- Solve for the witness \( w \) such that:
  \[
  A(w) ⋅ B(w) = C(w)
  \]

### **Step 2: Compute the proof elements**
- The proof consists of three group elements \( (A, B, C) \) computed as follows:
  \[
  A = g^{a + r_A τ}
  \]
  \[
  B = g^{b + r_B τ}
  \]
  \[
  C = g^{c + r_C τ + r_A r_B τ}
  \]
  where \( r_A, r_B, r_C \) are random scalars ensuring zero-knowledge.

### **Step 3: Output the proof**
- The prover outputs \( π = (A, B, C) \) as the proof.

---

## **3. Verification (Verifier's Side)**
The verifier checks that the proof is valid using the verification key (VK).

### **Step 1: Compute public input evaluation**
- Use the verification key to compute a weighted sum of public inputs.

### **Step 2: Perform pairings check**
- Verify the following bilinear pairing equation:
  \[
  e(A, B) = e(g^C, g)
  \]
  where \( e \) is a cryptographic pairing function.

### **Step 3: Accept or reject**
- If the pairing equation holds, the proof is valid.
- Otherwise, reject the proof.

# **PLONK**

## **1. Setup (Trusted Parameter Generation)**
The setup phase generates public parameters needed for proof generation and verification.

### **Step 1: Define the arithmetic circuit**
- Express the computation as a Rank-1 Constraint System (R1CS) or a set of custom gates.
- Convert it into a polynomial form using Lagrange interpolation.

### **Step 2: Generate the Structured Reference String (SRS)**
- The SRS contains powers of a secret scalar \( τ \) and is used for polynomial commitments.
- Unlike Groth16, PLONK’s SRS is **universal** and can be reused across circuits.
- It consists of:
  - **Prover Key (PK):** Helps in proof construction.
  - **Verifier Key (VK):** Helps in proof verification.

### **Step 3: Commit to polynomials**
- Commit to the witness polynomials using Kate commitments (evaluations in an elliptic curve group).

---

## **2. Proof Generation (Prover's Side)**
The prover constructs a zk-SNARK proof ensuring correctness of the computation.

### **Step 1: Compute witness values**
- Evaluate the constraint polynomials at secret points.
- Define wire polynomials \( a(X), b(X), c(X) \) corresponding to inputs and outputs.

### **Step 2: Compute permutation argument**
- PLONK uses a permutation argument to check that wires are correctly assigned.
- Compute the permutation product polynomial \( Z(X) \).

### **Step 3: Compute quotient polynomial**
- Construct a quotient polynomial \( t(X) \) that encodes constraint satisfaction.

### **Step 4: Generate proof elements**
- The prover computes and commits to:
  - Wire polynomials \( a(X), b(X), c(X) \)
  - Permutation polynomial \( Z(X) \)
  - Quotient polynomial \( t(X) \)
  - Evaluation proofs via Kate commitments

- The proof consists of commitments to these polynomials and evaluation proofs.

### **Step 5: Output the proof**
- The prover sends the proof \( π \) to the verifier.

---

## **3. Verification (Verifier's Side)**
The verifier checks the validity of the proof using polynomial commitments and pairings.

### **Step 1: Compute public input evaluation**
- Use the verification key to compute a weighted sum of public inputs.

### **Step 2: Perform polynomial checks**
- Verify that the committed polynomials satisfy the circuit constraints.
- Check that the permutation argument holds using the permutation polynomial \( Z(X) \).

### **Step 3: Use Kate commitment opening proof**
- Verify that polynomial evaluations are consistent using Kate commitments.
- This involves checking a bilinear pairing equation.

### **Step 4: Accept or reject**
- If all checks pass, accept the proof.
- Otherwise, reject the proof as invalid.

# **Bulletproofs**

## **1. Setup (Public Parameters Generation)**
Bulletproofs do not require a trusted setup, but they do rely on a publicly known set of parameters.

### **Step 1: Define the elliptic curve and generators**
- Choose an elliptic curve \( E \) over a finite field \( \mathbb{F}_q \).
- Select a generator \( G \) of a group of prime order \( p \) on \( E \).
- Define a second independent generator \( H \), which is typically derived from a hash function.

### **Step 2: Commit to the range proof base**
- Define an inner-product argument base \( G_1, G_2, \dots, G_n \) and \( H_1, H_2, \dots, H_n \).
- The generators \( H_i \) are determined using a Fiat-Shamir heuristic to ensure security.

### **Step 3: Establish a Pedersen Commitment scheme**
- The commitment scheme is defined as:
  \[
  C = vG + rH
  \]
  where:
  - \( v \) is the secret value to be proven within a range,
  - \( r \) is a blinding factor (random scalar),
  - \( C \) is the commitment sent to the verifier.

---

## **2. Proof Generation (Prover's Side)**
The prover generates a zero-knowledge proof that a committed value lies within a specific range (e.g., \( [0, 2^n -1] \)) without revealing the actual value.

### **Step 1: Encode the value as binary**
- The value \( v \) is encoded as an \( n \)-bit binary vector \( \mathbf{a}_L \) where:
  \[
  v = \sum_{i=0}^{n-1} a_{L,i} ⋅ 2^i
  \]
- Construct the complement vector \( \mathbf{a}_R = \mathbf{a}_L - \mathbf{1} \).

### **Step 2: Commit to the bit values**
- Compute the commitments:
  \[
  A = \langle \mathbf{a}_L, \mathbf{G} \rangle + \langle \mathbf{a}_R, \mathbf{H} \rangle + \alpha G
  \]
  \[
  S = \langle \mathbf{s}_L, \mathbf{G} \rangle + \langle \mathbf{s}_R, \mathbf{H} \rangle + \beta G
  \]
  where \( \alpha, \beta \) are random scalars used to ensure zero-knowledge.

### **Step 3: Generate challenge scalars**
- The verifier sends a challenge \( y, z \) (using the Fiat-Shamir heuristic).
- The prover computes vectors \( \mathbf{l}, \mathbf{r} \) and an inner-product proof.

### **Step 4: Compute the proof elements**
- Compute the response values using challenge \( x \) (another Fiat-Shamir challenge).
- The prover computes:
  \[
  T_1 = \langle \mathbf{l}, \mathbf{r} \rangle G + \gamma H
  \]
  and
  \[
  T_2 = x^2 \langle \mathbf{l}, \mathbf{r} \rangle G + \delta H
  \]

- These commitments ensure that the values remain within the specified range.

### **Step 5: Send the proof to the verifier**
The prover sends the commitments and responses, including:
- \( A, S, T_1, T_2 \),
- Inner product proof (which uses a logarithmic number of rounds to verify the computation).

---

## **3. Verification (Verifier's Side)**
The verifier checks the validity of the proof using the commitments and challenge responses.

### **Step 1: Compute challenge scalars**
- Using Fiat-Shamir heuristic, recompute \( y, z, x \).

### **Step 2: Verify the commitments**
- Check that the linear constraints hold for the committed values.
- Compute the expected inner product values and compare them against the provided proof.

### **Step 3: Verify inner product proof**
- Use logarithmic reduction to efficiently check that the inner product argument is valid.

### **Step 4: Accept or reject**
- If all checks pass, accept the proof.
- Otherwise, reject the proof as invalid.
