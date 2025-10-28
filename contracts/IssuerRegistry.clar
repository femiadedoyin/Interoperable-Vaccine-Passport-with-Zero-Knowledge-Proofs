(define-constant ERR-NOT-AUTHORIZED u200)
(define-constant ERR-ISSUER-EXISTS u201)
(define-constant ERR-ISSUER-NOT-FOUND u202)
(define-constant ERR-INVALID-NAME u203)
(define-constant ERR-INVALID-LOCATION u204)
(define-constant ERR-INVALID-CREDENTIAL u205)
(define-constant ERR-INVALID-PUBLIC-KEY u206)
(define-constant ERR-INVALID-STATUS u207)
(define-constant ERR-MAX-ISSUERS-EXCEEDED u208)
(define-constant ERR-INVALID-VERIFICATION-METHOD u209)

(define-data-var next-issuer-id uint u0)
(define-data-var max-issuers uint u500)
(define-data-var admin-principal principal tx-sender)

(define-map issuers
  uint
  {
    name: (string-utf8 100),
    location: (string-utf8 100),
    credential-hash: (buff 32),
    public-key: (buff 33),
    status: bool,
    verification-method: (string-utf8 50),
    registered-at: uint,
    updated-at: uint
  }
)

(define-map issuers-by-principal principal uint)
(define-map issuers-by-name (string-utf8 100) uint)

(define-read-only (get-issuer-by-id (id uint))
  (map-get? issuers id)
)

(define-read-only (get-issuer-by-principal (principal principal))
  (map-get? issuers-by-principal principal)
)

(define-read-only (get-issuer-by-name (name (string-utf8 100)))
  (map-get? issuers-by-name name)
)

(define-read-only (is-issuer-registered (principal principal))
  (is-some (map-get? issuers-by-principal principal))
)

(define-private (validate-name (name (string-utf8 100)))
  (if (and (> (len name) u0) (<= (len name) u100))
    (ok true)
    (err ERR-INVALID-NAME))
)

(define-private (validate-location (loc (string-utf8 100)))
  (if (and (> (len loc) u0) (<= (len loc) u100))
    (ok true)
    (err ERR-INVALID-LOCATION))
)

(define-private (validate-credential (hash (buff 32)))
  (if (is-eq (len hash) u32)
    (ok true)
    (err ERR-INVALID-CREDENTIAL))
)

(define-private (validate-public-key (key (buff 33)))
  (if (is-eq (len key) u33)
    (ok true)
    (err ERR-INVALID-PUBLIC-KEY))
)

(define-private (validate-verification-method (method (string-utf8 50)))
  (if (or (is-eq method u"WHO") (is-eq method u"CDC") (is-eq method u"EU-DCC") (is-eq method u"ICAO"))
    (ok true)
    (err ERR-INVALID-VERIFICATION-METHOD))
)

(define-public (register-issuer
  (name (string-utf8 100))
  (location (string-utf8 100))
  (credential-hash (buff 32))
  (public-key (buff 33))
  (verification-method (string-utf8 50))
)
  (let (
    (next-id (var-get next-issuer-id))
    (current-max (var-get max-issuers))
  )
    (asserts! (< next-id current-max) (err ERR-MAX-ISSUERS-EXCEEDED))
    (try! (validate-name name))
    (try! (validate-location location))
    (try! (validate-credential credential-hash))
    (try! (validate-public-key public-key))
    (try! (validate-verification-method verification-method))
    (asserts! (not (is-some (map-get? issuers-by-name name))) (err ERR-ISSUER-EXISTS))
    (asserts! (not (is-issuer-registered tx-sender)) (err ERR-ISSUER-EXISTS))
    (map-set issuers next-id
      {
        name: name,
        location: location,
        credential-hash: credential-hash,
        public-key: public-key,
        status: true,
        verification-method: verification-method,
        registered-at: block-height,
        updated-at: block-height
      }
    )
    (map-set issuers-by-principal tx-sender next-id)
    (map-set issuers-by-name name next-id)
    (var-set next-issuer-id (+ next-id u1))
    (print { event: "issuer-registered", id: next-id, principal: tx-sender })
    (ok next-id)
  )
)

(define-public (update-issuer
  (issuer-id uint)
  (name (string-utf8 100))
  (location (string-utf8 100))
  (verification-method (string-utf8 50))
)
  (let ((issuer (map-get? issuers issuer-id)))
    (match issuer
      data
        (let ((principal-id (map-get? issuers-by-principal tx-sender)))
          (asserts! (is-some principal-id) (err ERR-ISSUER-NOT-FOUND))
          (asserts! (is-eq (unwrap! principal-id (err ERR-ISSUER-NOT-FOUND)) issuer-id) (err ERR-NOT-AUTHORIZED))
          (try! (validate-name name))
          (try! (validate-location location))
          (try! (validate-verification-method verification-method))
          (let ((old-name (get name data)))
            (if (not (is-eq old-name name))
              (begin
                (map-delete issuers-by-name old-name)
                (map-set issuers-by-name name issuer-id)
              )
              (ok true)
            )
          )
          (map-set issuers issuer-id
            (merge data
              {
                name: name,
                location: location,
                verification-method: verification-method,
                updated-at: block-height
              }
            )
          )
          (print { event: "issuer-updated", id: issuer-id })
          (ok true)
        )
      (err ERR-ISSUER-NOT-FOUND)
    )
  )
)

(define-public (deactivate-issuer (issuer-id uint))
  (let ((issuer (map-get? issuers issuer-id)))
    (match issuer
      data
        (begin
          (asserts! (is-eq tx-sender (var-get admin-principal)) (err ERR-NOT-AUTHORIZED))
          (map-set issuers issuer-id (merge data { status: false, updated-at: block-height }))
          (print { event: "issuer-deactivated", id: issuer-id })
          (ok true)
        )
      (err ERR-ISSUER-NOT-FOUND)
    )
  )
)

(define-public (reactivate-issuer (issuer-id uint))
  (let ((issuer (map-get? issuers issuer-id)))
    (match issuer
      data
        (begin
          (asserts! (is-eq tx-sender (var-get admin-principal)) (err ERR-NOT-AUTHORIZED))
          (map-set issuers issuer-id (merge data { status: true, updated-at: block-height }))
          (print { event: "issuer-reactivated", id: issuer-id })
          (ok true)
        )
      (err ERR-ISSUER-NOT-FOUND)
    )
  )
)

(define-public (set-admin (new-admin principal))
  (begin
    (asserts! (is-eq tx-sender (var-get admin-principal)) (err ERR-NOT-AUTHORIZED))
    (var-set admin-principal new-admin)
    (ok true)
  )
)

(define-public (get-issuer-count)
  (ok (var-get next-issuer-id))
)