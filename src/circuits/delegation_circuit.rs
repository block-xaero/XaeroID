use ark_bn254::Fr;

// For granting roles without revealing the delegator's identity
struct DelegationCircuit {
    delegator_role: Option<u8>,      // Private: your role
    target_role: Option<u8>,         // Private: role you're granting
    min_delegation_role: Option<u8>, // Public: minimum role needed to delegate
    delegation_proof: Option<Fr>,    // Public: commitment to delegation
}
// Proves: "Someone with sufficient authority granted this role"
