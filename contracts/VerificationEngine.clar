(define-constant ERR-NOT-AUTHORIZED u100)
(define-constant ERR-INVALID-PROOF u101)
(define-constant ERR-INVALID-VK u102)
(define-constant ERR-INVALID-PUBLIC-INPUT u103)
(define-constant ERR-PROOF-ALREADY-USED u104)
(define-constant ERR-ISSUER-NOT-REGISTERED u105)
(define-constant ERR-USER-NOT-REGISTERED u106)
(define-constant ERR-INVALID-TIMESTAMP u107)
(define-constant ERR-VERIFICATION-FAILED u108)
(define-constant ERR-INVALID-CHALLENGE u109)
(define-constant ERR-INVALID-PROOF-LENGTH u110)
(define-constant ERR-INVALID-VK-PARAMS u111)
(define-constant ERR-INVALID-STATUS u112)
(define-constant ERR-INVALID-EXPIRY u113)
(define-constant ERR-PROOF-EXPIRED u114)
(define-constant ERR-INVALID-VACCINE-TYPE u115)
(define-constant ERR-INVALID-DOSE-COUNT u116)
(define-constant ERR-INVALID-ISSUER-SIG u117)
(define-constant ERR-MAX-PROOFS-EXCEEDED u118)
(define-constant ERR-INVALID-HASH u119)
(define-constant ERR-INVALID-PROOF-ID u120)

(define-data-var next-proof-id uint u0)
(define-data-var max-proofs uint u10000)
(define-data-var verification-fee uint u500)
(define-data-var admin-principal principal tx-sender)

(define-map proofs
  uint
  {
    user: principal,
    issuer: principal,
    proof-hash: (buff 32),
    public-input: (buff 64),
    timestamp: uint,
    expiry: uint,
    status: bool,
    vaccine-type: (string-utf8 50),
    dose-count: uint,
    challenge: (buff 32),
    vk-params: (buff 128)
  }
)

(define-map proofs-by-hash
  (buff 32)
  uint
)

(define-map issuers
  principal
  {
    name: (string-utf8 100),
    verified: bool,
    sig-key: (buff 33)
  }
)

(define-map verification-logs
  uint
  {
    proof-id: uint,
    verifier: principal,
    timestamp: uint,
    result: bool
  }
)

(define-read-only (get-proof (id uint))
  (map-get? proofs id)
)

(define-read-only (get-issuer (issuer principal))
  (map-get? issuers issuer)
)

(define-read-only (get-verification-log (log-id uint))
  (map-get? verification-logs log-id)
)

(define-read-only (is-proof-registered (hash (buff 32)))
  (is-some (map-get? proofs-by-hash hash))
)

(define-private (validate-proof-length (proof (buff 256)))
  (if (is-eq (len proof) u256)
    (ok true)
    (err ERR-INVALID-PROOF-LENGTH))
)

(define-private (validate-vk-params (vk (buff 128)))
  (if (is-eq (len vk) u128)
    (ok true)
    (err ERR-INVALID-VK-PARAMS))
)

(define-private (validate-public-input (input (buff 64)))
  (if (is-eq (len input) u64)
    (ok true)
    (err ERR-INVALID-PUBLIC-INPUT))
)

(define-private (validate-timestamp (ts uint))
  (if (>= ts block-height)
    (ok true)
    (err ERR-INVALID-TIMESTAMP))
)

(define-private (validate-expiry (exp uint))
  (if (> exp block-height)
    (ok true)
    (err ERR-INVALID-EXPIRY))
)

(define-private (validate-challenge (chal (buff 32)))
  (if (is-eq (len chal) u32)
    (ok true)
    (err ERR-INVALID-CHALLENGE))
)

(define-private (validate-vaccine-type (vtype (string-utf8 50)))
  (if (or (is-eq vtype u"COVID-19") (is-eq vtype u"FLU") (is-eq vtype u"HEPATITIS"))
    (ok true)
    (err ERR-INVALID-VACCINE-TYPE))
)

(define-private (validate-dose-count (count uint))
  (if (and (>= count u1) (<= count u5))
    (ok true)
    (err ERR-INVALID-DOSE-COUNT))
)

(define-private (validate-issuer-sig (sig (buff 65)))
  (if (is-eq (len sig) u65)
    (ok true)
    (err ERR-INVALID-ISSUER-SIG))
)

(define-private (validate-hash (hash (buff 32)))
  (if (is-eq (len hash) u32)
    (ok true)
    (err ERR-INVALID-HASH))
)

(define-private (mock-zkp-verify (proof (buff 256)) (vk (buff 128)) (input (buff 64)))
  (ok true)
)

(define-public (register-issuer (name (string-utf8 100)) (sig-key (buff 33)))
  (begin
    (asserts! (is-eq tx-sender (var-get admin-principal)) (err ERR-NOT-AUTHORIZED))
    (asserts! (not (is-some (map-get? issuers tx-sender))) (err ERR-ISSUER-NOT-REGISTERED))
    (map-set issuers tx-sender { name: name, verified: true, sig-key: sig-key })
    (ok true)
  )
)

(define-public (submit-proof
  (proof-hash (buff 32))
  (public-input (buff 64))
  (expiry uint)
  (vaccine-type (string-utf8 50))
  (dose-count uint)
  (challenge (buff 32))
  (vk-params (buff 128))
  (issuer-sig (buff 65))
)
  (let (
    (next-id (var-get next-proof-id))
    (issuer (map-get? issuers tx-sender))
  )
    (asserts! (< next-id (var-get max-proofs)) (err ERR-MAX-PROOFS-EXCEEDED))
    (try! (validate-hash proof-hash))
    (try! (validate-public-input public-input))
    (try! (validate-expiry expiry))
    (try! (validate-vaccine-type vaccine-type))
    (try! (validate-dose-count dose-count))
    (try! (validate-challenge challenge))
    (try! (validate-vk-params vk-params))
    (try! (validate-issuer-sig issuer-sig))
    (asserts! (is-some issuer) (err ERR-ISSUER-NOT-REGISTERED))
    (asserts! (not (is-proof-registered proof-hash)) (err ERR-PROOF-ALREADY-USED))
    (try! (stx-transfer? (var-get verification-fee) tx-sender (var-get admin-principal)))
    (map-set proofs next-id
      {
        user: tx-sender,
        issuer: tx-sender,
        proof-hash: proof-hash,
        public-input: public-input,
        timestamp: block-height,
        expiry: expiry,
        status: true,
        vaccine-type: vaccine-type,
        dose-count: dose-count,
        challenge: challenge,
        vk-params: vk-params
      }
    )
    (map-set proofs-by-hash proof-hash next-id)
    (var-set next-proof-id (+ next-id u1))
    (print { event: "proof-submitted", id: next-id })
    (ok next-id)
  )
)

(define-public (verify-proof (proof-id uint) (proof (buff 256)) (public-input (buff 64)))
  (let (
    (p (map-get? proofs proof-id))
    (log-id (var-get next-proof-id))
  )
    (match p
      proof-data
        (begin
          (asserts! (is-eq (get status proof-data) true) (err ERR-INVALID-STATUS))
          (asserts! (< block-height (get expiry proof-data)) (err ERR-PROOF-EXPIRED))
          (try! (validate-proof-length proof))
          (try! (validate-public-input public-input))
          (asserts! (is-eq public-input (get public-input proof-data)) (err ERR-INVALID_PUBLIC-INPUT))
          (try! (mock-zkp-verify proof (get vk-params proof-data) public-input))
          (map-set verification-logs log-id
            {
              proof-id: proof-id,
              verifier: tx-sender,
              timestamp: block-height,
              result: true
            }
          )
          (print { event: "proof-verified", id: proof-id })
          (ok true)
        )
      (err ERR-INVALID-PROOF-ID)
    )
  )
)

(define-public (revoke-proof (proof-id uint))
  (let ((p (map-get? proofs proof-id)))
    (match p
      proof-data
        (begin
          (asserts! (is-eq (get issuer proof-data) tx-sender) (err ERR-NOT-AUTHORIZED))
          (map-set proofs proof-id (merge proof-data { status: false }))
          (print { event: "proof-revoked", id: proof-id })
          (ok true)
        )
      (err ERR-INVALID-PROOF-ID)
    )
  )
)

(define-public (set-verification-fee (new-fee uint))
  (begin
    (asserts! (is-eq tx-sender (var-get admin-principal)) (err ERR-NOT-AUTHORIZED))
    (var-set verification-fee new-fee)
    (ok true)
  )
)

(define-public (get-proof-count)
  (ok (var-get next-proof-id))
)