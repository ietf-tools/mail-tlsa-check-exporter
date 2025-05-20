import crypto from 'node:crypto'
import dns from 'node:dns/promises'
import net from 'node:net'
import tls from 'node:tls'
import http from 'node:http'

const SMTP_HOSTNAME = process.env.MTCE_SMTP_HOSTNAME
const SMTP_PORT = parseInt(process.env.MTCE_SMTP_PORT ?? 587)
const IMAP_HOSTNAME = process.env.MTCE_IMAP_HOSTNAME
const IMAP_PORT = parseInt(process.env.MTCE_IMAP_PORT ?? 143)
const TLSA_RECORD = process.env.MTCE_TLSA_RECORD ?? `_25._tcp.${SMTP_HOSTNAME}`
const CHECK_TIMEOUT = parseInt(process.env.MTCE_CHECK_TIMEOUT ?? 15000)
const IPV4_ENABLED = process.env.MTCE_IPV4_ENABLED?.toLowerCase() === 'true'
const IPV6_ENABLED = process.env.MTCE_IPV6_ENABLED?.toLowerCase() === 'true'

// Init Check

if (!SMTP_HOSTNAME && !process.env.MTCE_TLSA_RECORD) {
  console.error('Must provide at least one of MTCE_TLSA_RECORD or MTCE_SMTP_HOSTNAME env variable!')
  process.exit(1)
}
if (!IMAP_HOSTNAME && !SMTP_HOSTNAME) {
  console.error('Must provide at least one of MTCE_SMTP_HOSTNAME or MTCE_IMAP_HOSTNAME env variable!')
  process.exit(1)
}

/**
 * Fetch hash digest from TLSA record
 * 
 * @returns {Promise<String>} Hash digest
 */
async function fetchTLSA () {
  console.info('Fetching TLSA record...')
  return new Promise(async (resolve, reject) => {
    const fetchTimer = setTimeout(() => {
      console.warn('-> Timeout Error - Closing connection...')
      reject({
        up: 1,
        digest: '',
        seconds: CHECK_TIMEOUT / 1000
      })
    }, CHECK_TIMEOUT)

    performance.mark('tlsa_start')
    try {
      const tlsaRecord = await dns.resolveTlsa(TLSA_RECORD)
      performance.mark('tlsa_end')
      clearTimeout(fetchTimer)

      const tlsaData = Buffer.from(tlsaRecord[0].data).toString('hex')
      console.info(`TLSA record hash digest: ${tlsaData}`)

      resolve({
        up: 1,
        digest: tlsaData,
        seconds: performance.measure('tlsa', 'tlsa_start', 'tlsa_end').duration / 1000
      })
    } catch (err) {
      performance.mark('tlsa_end')
      reject({
        up: 0,
        digest: '',
        seconds: performance.measure('tlsa', 'tlsa_start', 'tlsa_end').duration / 1000
      })
    }
  })
}

/**
 * Validate SMTP Certificate
 * 
 * @param {Number} ipFamily Whether to connect via IPv4 or IPv6
 * @param {String} expectedHash The hash digest to expect
 * @returns {Promise} Promise that resolves on success
 */
async function validateSMTP (ipFamily = 4, expectedHash) {
  console.info(`SMTP Validation Check - ${SMTP_HOSTNAME}:${SMTP_PORT} via IPv${ipFamily}`)
  return new Promise((resolve, reject) => {
    try {
      performance.mark('smtp_start')
      const client = new net.Socket()
      let step = null

      const clientTimer = setTimeout(() => {
        if (client) {
          console.warn('-> Timeout Error - Closing connection... [ ERROR ]')
          client.end()
          resolve({
            up: 0,
            valid: 0,
            digest: '',
            seconds: CHECK_TIMEOUT / 1000
          })
        }
      }, CHECK_TIMEOUT)

      client.on('data', resp => {
        const respStr = resp.toString()
        if (step === null && respStr.indexOf(`220 ${SMTP_HOSTNAME} ESMTP`) === 0) {
          console.info('-> Sending EHLO...')
          step = 'EHLO'
          client.write('EHLO ietf-synthetics-probe\n')
        } else if (step === 'EHLO' && respStr.indexOf('250-STARTTLS') >= 0) {
          console.info('-> Sending STARTTLS...')
          step = 'STARTTLS'
          client.write('STARTTLS\n')
        } else if (step === 'STARTTLS' && respStr.indexOf('220 ') === 0) {
          console.info('-> Switching to TLS...')
          step = 'TLS'
          const clientTls = tls.connect({
            socket: client
          }, () => {
            console.info('-> TLS connected.')
            const cert = clientTls.getPeerCertificate(true)
            clearTimeout(clientTimer)
            client.end()
            performance.mark('smtp_end')

            // -> Validate expiration
            if (new Date(cert.valid_from) > new Date()) {
              client.end()
              console.warn('Certificate has invalid date range. valid_from is in the future! [ ERROR ]')
              return resolve({
                up: 1,
                valid: 0,
                digest: '',
                seconds: performance.measure('smtp', 'smtp_start', 'smtp_end').duration / 1000
              })
            } else if (new Date(cert.valid_to) <= new Date()) {
              client.end()
              console.warn('Certificate has expired and is no longer valid! [ ERROR ]')
              return resolve({
                up: 1,
                valid: 0,
                digest: '',
                seconds: performance.measure('smtp', 'smtp_start', 'smtp_end').duration / 1000
              })
            }

            // -> Validate hash digest
            const certPemEncoded = pemEncode(cert.raw.toString('base64'))
            const certPubKeyDer = crypto.createPublicKey(certPemEncoded).export({ type: 'spki', format: 'der' })
            const pubkeyHash = crypto.createHash('sha256').update(certPubKeyDer).digest('hex')

            if (expectedHash === pubkeyHash) {
              console.info('SMTP TLS Certificate digest matches TLSA record. [ VALID ]')
            } else {
              console.info(`SMTP TLS Certificate digest does not match expected TLSA record! Expected "${expectedHash}" but received "${pubkeyHash}" [ ERROR ]`)
            }
            resolve({
              up: 1,
              valid: expectedHash === pubkeyHash ? 1 : 0,
              digest: pubkeyHash,
              seconds: performance.measure('smtp', 'smtp_start', 'smtp_end').duration / 1000
            })
          })
        }
      })

      client.on('connect', () => {
        console.info(`-> Connected to ${SMTP_HOSTNAME}:${SMTP_PORT} via IPv${ipFamily}`)
      })

      client.on('error', err => {
        performance.mark('smtp_end')
        console.warn(err)
        resolve({
          up: 0,
          valid: 0,
          digest: '',
          seconds: performance.measure('smtp', 'smtp_start', 'smtp_end').duration / 1000
        })
      })

      client.connect({
        host: SMTP_HOSTNAME,
        port: SMTP_PORT,
        family: ipFamily
      })
    } catch (err) {
      if (client) {
        client.end()
      }
      performance.mark('smtp_end')
      console.warn(err)
      resolve({
        up: 0,
        valid: 0,
        digest: '',
        seconds: performance.measure('smtp', 'smtp_start', 'smtp_end').duration / 1000
      })
    }
  })
}

/**
 * Validate IMAP Certificate
 * 
 * @param {Number} ipFamily Whether to connect via IPv4 or IPv6
 * @param {String} expectedHash The hash digest to expect
 * @returns {Promise} Promise that resolves on success
 */
async function validateIMAP (ipFamily = 4, expectedHash) {
  console.info(`IMAP Validation Check - ${IMAP_HOSTNAME}:${IMAP_PORT} via IPv${ipFamily}`)
  return new Promise((resolve, reject) => {
    try {
      performance.mark('imap_start')
      const client = new net.Socket()
      let step = null

      const clientTimer = setTimeout(() => {
        if (client) {
          console.warn('-> Timeout Error - Closing connection... [ ERROR ]')
          client.end()
          resolve({
            up: 0,
            valid: 0,
            digest: '',
            seconds: CHECK_TIMEOUT / 1000
          })
        }
      }, CHECK_TIMEOUT)

      client.on('data', resp => {
        const respStr = resp.toString()
        if (step === null && respStr.indexOf('STARTTLS') >= 0) {
          console.info('-> Sending STARTTLS...')
          step = 'STARTTLS'
          client.write('. STARTTLS\r\n')
        } else if (step === 'STARTTLS' && respStr.indexOf('OK ') >= 0) {
          console.info('-> Switching to TLS...')
          step = 'TLS'
          const clientTls = tls.connect({
            socket: client
          }, () => {
            console.info('-> TLS connected.')
            const cert = clientTls.getPeerCertificate(true)
            clearTimeout(clientTimer)
            client.end()
            performance.mark('imap_end')

            // -> Validate expiration
            if (new Date(cert.valid_from) > new Date()) {
              client.end()
              console.warn('Certificate has invalid date range. valid_from is in the future! [ ERROR ]')
              return resolve({
                up: 1,
                valid: 0,
                digest: '',
                seconds: performance.measure('imap', 'imap_start', 'imap_end').duration / 1000
              })
            } else if (new Date(cert.valid_to) <= new Date()) {
              client.end()
              console.warn('Certificate has expired and is no longer valid! [ ERROR ]')
              return resolve({
                up: 1,
                valid: 0,
                digest: '',
                seconds: performance.measure('imap', 'imap_start', 'imap_end').duration / 1000
              })
            }

            // -> Validate hash digest
            const certPemEncoded = pemEncode(cert.raw.toString('base64'))
            const certPubKeyDer = crypto.createPublicKey(certPemEncoded).export({ type: 'spki', format: 'der' })
            const pubkeyHash = crypto.createHash('sha256').update(certPubKeyDer).digest('hex')

            if (expectedHash === pubkeyHash) {
              console.info('IMAP TLS Certificate digest matches TLSA record. [ VALID ]')
            } else {
              console.info(`IMAP TLS Certificate digest does not match expected TLSA record! Expected "${expectedHash}" but received "${pubkeyHash}" [ ERROR ]`)
            }
            resolve({
              up: 1,
              valid: expectedHash === pubkeyHash ? 1 : 0,
              digest: pubkeyHash,
              seconds: performance.measure('imap', 'imap_start', 'imap_end').duration / 1000
            })
          })
        }
      })

      client.on('connect', () => {
        console.info(`-> Connected to ${IMAP_HOSTNAME}:${IMAP_PORT} via IPv${ipFamily}`)
      })

      client.on('error', err => {
        performance.mark('imap_end')
        console.warn(err)
        resolve({
          up: 0,
          valid: 0,
          digest: '',
          seconds: performance.measure('imap', 'imap_start', 'imap_end').duration / 1000
        })
      })

      client.connect({
        host: IMAP_HOSTNAME,
        port: IMAP_PORT,
        family: ipFamily
      })
    } catch (err) {
      if (client) {
        client.end()
      }
      performance.mark('imap_end')
      console.warn(err)
      resolve({
        up: 0,
        valid: 0,
        digest: '',
        seconds: performance.measure('imap', 'imap_start', 'imap_end').duration / 1000
      })
    }
  })
}

/**
 * Encode to PEM format
 * 
 * @param {*} str 
 * @param {*} docType 
 * @returns 
 */
function pemEncode (str, docType = 'CERTIFICATE') {
  const ret = []
  for (let i = 1; i <= str.length; i++) {
    ret.push(str[i - 1])
    if (i % 64 === 0 && i < str.length) {
      ret.push('\n')
    }
  }
  return `-----BEGIN ${docType}-----\n${ret.join('')}\n-----END ${docType}-----`
}

// ------------------------------------------------------------
// HTTP SERVER
// ------------------------------------------------------------

const server = http.createServer(async (req, res) => {
  if (req.url === '/metrics') {
    try {
      const results = []
  
      // -> TLSA Record Fetch
      const tlsaResult = await fetchTLSA()
      results.push('# HELP mtce_tlsa_status TLSA record fetch status (1 = up, 0 = failed)')
      results.push('# TYPE mtce_tlsa_status gauge')
      results.push(`mtce_tlsa_status{tlsa_digest="${tlsaResult.digest}"} ${tlsaResult.up}`)
  
      results.push('# HELP mtce_tlsa_fetch_seconds TLSA record fetch duration in seconds')
      results.push('# TYPE mtce_tlsa_fetch_seconds gauge')
      results.push(`mtce_tlsa_fetch_seconds{tlsa_digest="${tlsaResult.digest}"} ${tlsaResult.seconds}`)

      // -> SMTP Check
      if (SMTP_HOSTNAME) {
        const smtpV4Result = IPV4_ENABLED ? await validateSMTP(4, tlsaResult.digest) : {}
        const smtpV6Result = IPV6_ENABLED ? await validateSMTP(6, tlsaResult.digest) : {}
        
        results.push('# HELP mtce_smtp_status SMTP server status (1 = up, 0 = failed)')
        results.push('# TYPE mtce_smtp_status gauge')
        if (IPV4_ENABLED) {
          results.push(`mtce_smtp_status{ip="v4",tlsa_digest="${tlsaResult.digest}"} ${smtpV4Result.up}`)
        }
        if (IPV6_ENABLED) {
          results.push(`mtce_smtp_status{ip="v6",tlsa_digest="${tlsaResult.digest}"} ${smtpV6Result.up}`)
        }
  
        results.push('# HELP mtce_smtp_cert_status SMTP certificate status (1 = valid, 0 = invalid)')
        results.push('# TYPE mtce_smtp_cert_status gauge')
        if (IPV4_ENABLED) {
          results.push(`mtce_smtp_cert_status{ip="v4",tlsa_digest="${tlsaResult.digest}",cert_digest="${smtpV4Result.digest}"} ${smtpV4Result.valid}`)
        }
        if (IPV6_ENABLED) {
          results.push(`mtce_smtp_cert_status{ip="v6",tlsa_digest="${tlsaResult.digest}",cert_digest="${smtpV6Result.digest}"} ${smtpV6Result.valid}`)
        }

        results.push('# HELP mtce_smtp_seconds SMTP check duration in seconds')
        results.push('# TYPE mtce_smtp_seconds gauge')
        if (IPV4_ENABLED) {
          results.push(`mtce_smtp_seconds{ip="v4",tlsa_digest="${tlsaResult.digest}"} ${smtpV4Result.seconds}`)
        }
        if (IPV6_ENABLED) {
          results.push(`mtce_smtp_seconds{ip="v6",tlsa_digest="${tlsaResult.digest}"} ${smtpV6Result.seconds}`)
        }
      }

      // -> IMAP Check
      if (IMAP_HOSTNAME) {
        const imapV4Result = IPV4_ENABLED ? await validateIMAP(4, tlsaResult.digest) : {}
        const imapV6Result = IPV6_ENABLED ? await validateIMAP(6, tlsaResult.digest) : {}

        results.push('# HELP mtce_imap_status IMAP server status (1 = up, 0 = failed)')
        results.push('# TYPE mtce_imap_status gauge')
        if (IPV4_ENABLED) {
          results.push(`mtce_imap_status{ip="v4",tlsa_digest="${tlsaResult.digest}"} ${imapV4Result.up}`)
        }
        if (IPV6_ENABLED) {
          results.push(`mtce_imap_status{ip="v6",tlsa_digest="${tlsaResult.digest}"} ${imapV6Result.up}`)
        }

        results.push('# HELP mtce_imap_cert_status IMAP certificate status (1 = valid, 0 = invalid)')
        results.push('# TYPE mtce_imap_cert_status gauge')
        if (IPV4_ENABLED) {
          results.push(`mtce_imap_cert_status{ip="v4",tlsa_digest="${tlsaResult.digest}",cert_digest="${imapV4Result.digest}"} ${imapV4Result.valid}`)
        }
        if (IPV6_ENABLED) {
          results.push(`mtce_imap_cert_status{ip="v6",tlsa_digest="${tlsaResult.digest}",cert_digest="${imapV6Result.digest}"} ${imapV6Result.valid}`)
        }

        results.push('# HELP mtce_imap_seconds IMAP check duration in seconds')
        results.push('# TYPE mtce_imap_seconds gauge')
        if (IPV4_ENABLED) {
          results.push(`mtce_imap_seconds{ip="v4",tlsa_digest="${tlsaResult.digest}"} ${imapV4Result.seconds}`)
        }
        if (IPV6_ENABLED) {
          results.push(`mtce_imap_seconds{ip="v6",tlsa_digest="${tlsaResult.digest}"} ${imapV6Result.seconds}`)
        }
      }
  
      res.writeHead(200, { 'Content-Type': 'text/plain' })
      res.end(results.join('\n'))
    } catch (err) {
      res.writeHead(500, { 'Content-Type': 'text/plain' })
      res.end('ERROR: ' + err.message)
    }
  
    performance.clearMarks()
    performance.clearMeasures()
  } else {
    res.writeHead(200, { 'Content-Type': 'text/plain' })
    res.end('Mail TLSA Check Exporter\n------------------------\nMetrics are available at path /metrics')
  }
})
const serverPort = parseInt(process.env.MTCE_SERVER_PORT || 19309)
server.listen(serverPort, () => {
  console.log(`MAIL-TLSA-CHECK-EXPORTER started on port ${serverPort}`)
})