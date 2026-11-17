The Linux TPM signer checks that a persistent P-256 key was generated in the
TPM, is fixed to that TPM and its parent, and permits signing. Status and
sign requests refuse keys missing these attributes. Refs #107.
