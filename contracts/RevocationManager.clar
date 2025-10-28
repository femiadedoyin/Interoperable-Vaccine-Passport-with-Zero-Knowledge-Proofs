(define-constant ERR-NOT-AUTHORIZED u300)
(define-constant ERR-PROOF-NOT-FOUND u301)
(define-constant ERR-PROOF-ALREADY-REVOKED u302)
(define-constant ERR-INVALID-REASON u303)
(define-constant ERR-INVALID-TIMESTAMP u304)
(define-constant ERR-ISSUER-MISMATCH u305)
(define-constant ERR-MAX-REVOCATIONS-EXCEEDED u306)
(define-constant ERR-INVALID-PROOF-ID u307)

(define-data-var next-revocation-id uint u0)
(define-data-var max-revocations uint u10000)

(define-map revocations
  uint
  {
    proof-id: uint,
    issuer: principal,
    reason: (string-utf8 200),
    timestamp: uint,
    status: bool
  }
)

(define-map revocations-by-proof uint uint)
(define-map active-revocations principal (list 1000 uint))

(define-read-only (get-revocation (id uint))
  (map-get? revocations id)
)

(define-read-only (get-revocation-by-proof (proof-id uint))
  (map-get? revocations-by-proof proof-id)
)

(define-read-only (is-proof-revoked (proof-id uint))
  (is-some (map-get? revocations-by-proof proof-id))
)

(define-private (validate-reason (reason (string-utf8 200)))
  (if (and (> (len reason) u0) (<= (len reason) u200))
    (ok true)
    (err ERR-INVALID-REASON))
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
    (ok true)
    (err ERR-INVALID-TIMESTAMP))
)

(define-public (revoke-proof
  (proof-id uint)
  (reason (string-utf8 200))
)
  (let (
    (next-id (var-get next-revocation-id))
    (current-max (var-get max-revocations))
    (existing (map-get? revocations-by-proof proof-id))
  )
    (asserts! (< next-id current-max) (err ERR-MAX-REVOCATIONS-EXCEEDED))
    (asserts! (is-none existing) (err ERR-PROOF-ALREADY-REVOKED))
    (try! (validate-reason reason))
    (let ((proof (contract-call? .VerificationEngine get-proof proof-id)))
      (match proof
        p
          (begin
            (asserts! (is-eq (get issuer p) tx-sender) (err ERR-ISSUER-MISMATCH))
            (asserts! (get status p) (err ERR-PROOF-ALREADY-REVOKED))
            (map-set revocations next-id
              {
                proof-id: proof-id,
                issuer: tx-sender,
                reason: reason,
                timestamp: block-height,
                status: true
              }
            )
            (map-set revocations-by-proof proof-id next-id)
            (var-set next-revocation-id (+ next-id u1))
            (try! (contract-call? .VerificationEngine revoke-proof proof-id))
            (print { event: "proof-revoked", proof-id: proof-id, revocation-id: next-id })
            (ok next-id)
          )
        (err ERR-PROOF-NOT-FOUND)
      )
    )
  )
)

(define-public (get-revocation-count)
  (ok (var-get next-revocation-id))
)