/*
 * @adonisjs/shield
 *
 * (c) AdonisJS
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

import type { ViewContract } from '@adonisjs/view/types'
import type { HttpContext } from '@adonisjs/core/http'
import type { Encryption } from '@adonisjs/core/encryption'
import type { CsrfOptions } from '../types.js'

import Tokens from 'csrf'
import debug from '../debug.js'
import { noop } from '../noop.js'
import { E_BAD_CSRF_TOKEN } from '../exceptions.js'

/**
 * A class to encapsulate the logic of verifying and generating
 * CSRF tokens.
 */
export class Csrf {
  /**
   * Factory for generate csrf secrets and tokens
   */
  #tokens = new Tokens()

  /**
   * An array of methods on which the CSRF validation should be enforced.
   */
  #whitelistedMethods: NonNullable<CsrfOptions['methods']>

  /**
   * An array of routes to be ignored from CSRF validation
   */
  #routesToIgnore: NonNullable<CsrfOptions['exceptRoutes']>

  /**
   * Name of the csrf section key stored inside the session store
   */
  #secretSessionKey = 'csrf-secret'

  /**
   * Csrf options
   */
  #options: CsrfOptions

  /**
   * Reference to the encryption module
   */
  #encryption: Encryption

  /**
   * Reference to the view provider
   */
  #viewProvider?: ViewContract

  constructor(options: CsrfOptions, encryption: Encryption, viewProvider?: ViewContract) {
    this.#options = options
    this.#encryption = encryption
    this.#viewProvider = viewProvider

    this.#routesToIgnore = this.#options.exceptRoutes || []
    this.#whitelistedMethods = (this.#options.methods || []).map((method) => method.toLowerCase())
  }

  /**
   * Find if a request should be validated or not
   */
  private shouldValidateRequest(ctx: HttpContext) {
    /**
     * Do not validate when whitelisted methods are defined and current
     * method is not part of the white list
     */
    if (
      this.#whitelistedMethods.length &&
      !this.#whitelistedMethods.includes(ctx.request.method().toLowerCase())
    ) {
      return false
    }

    /**
     * Invoke callback when defined
     */
    if (typeof this.#routesToIgnore === 'function') {
      return !this.#routesToIgnore(ctx)
    }

    /**
     * Do not validate when current request route is ignored inside `routesToIgnore`
     * array
     */
    if (this.#routesToIgnore.includes(ctx.route!.pattern)) {
      return false
    }

    return true
  }

  /**
   * Read csrf token from one of the following sources.
   *
   * - `_csrf` input
   * - `x-csrf-token` header
   * - Or `x-xsrf-token` header. The header value must be set by
   *   reading the `XSRF-TOKEN` cookie.
   */
  private getCsrfTokenFromRequest({ request }: HttpContext): string | null {
    if (request.input('_csrf')) {
      debug('retrieved token from "_csrf" input')
      return request.input('_csrf')
    }

    if (request.header('x-csrf-token')) {
      debug('retrieved token from "x-csrf-token" header')
      return request.header('x-csrf-token')!
    }

    /**
     * Only entertain header based on cookie value, when `enableXsrfCookie`
     * is enabled
     */
    if (!this.#options.enableXsrfCookie) {
      return null
    }

    const encryptedToken = request.header('x-xsrf-token')
    if (typeof encryptedToken !== 'string' || !encryptedToken) {
      return null
    }

    debug('retrieved token from "x-xsrf-token" header')
    return this.#encryption.decrypt(decodeURIComponent(encryptedToken).slice(2), 'XSRF-TOKEN')
  }

  /**
   * Share csrf helper methods with the view engine.
   */
  private shareCsrfViewLocals(ctx: HttpContext): void {
    if (!ctx.view || !this.#viewProvider) {
      return
    }

    ctx.view.share({
      csrfToken: ctx.request.csrfToken,
      csrfMeta: () => {
        return this.#viewProvider!.GLOBALS.safe(
          `<meta name='csrf-token' content='${ctx.request.csrfToken}'>`
        )
      },
      csrfField: () => {
        return this.#viewProvider!.GLOBALS.safe(
          `<input type='hidden' name='_csrf' value='${ctx.request.csrfToken}'>`
        )
      },
    })
  }

  /**
   * Generate a new csrf token using the csrf secret extracted from session.
   */
  private generateCsrfToken(csrfSecret: string): string {
    return this.#tokens.create(csrfSecret)
  }

  /**
   * Return the existing CSRF secret from the session or create a
   * new one. Newly created secret is persisted to session at
   * the same time
   */
  private async getCsrfSecret(ctx: HttpContext): Promise<string> {
    let csrfSecret = ctx.session.get(this.#secretSessionKey)

    if (!csrfSecret) {
      csrfSecret = await this.#tokens.secret()
      ctx.session.put(this.#secretSessionKey, csrfSecret)
    }

    return csrfSecret
  }

  /**
   * Handle csrf verification. First, get the secret,
   * next, check if the request method should be
   * verified. Next, attach the newly generated
   * csrf token to the request object.
   */
  async handle(ctx: HttpContext): Promise<void> {
    const csrfSecret = await this.getCsrfSecret(ctx)

    /**
     * Validate current request before moving forward
     */
    if (this.shouldValidateRequest(ctx)) {
      const csrfToken = this.getCsrfTokenFromRequest(ctx)
      if (!csrfToken || !this.#tokens.verify(csrfSecret, csrfToken)) {
        throw new E_BAD_CSRF_TOKEN()
      }
    }

    /**
     * Add csrf token on the request
     */
    ctx.request.csrfToken = this.generateCsrfToken(csrfSecret)

    /**
     * Set it as a cookie
     */
    if (this.#options.enableXsrfCookie) {
      const cookieOptions = Object.assign({}, this.#options.cookieOptions, {
        httpOnly: false,
      })
      ctx.response.encryptedCookie('XSRF-TOKEN', ctx.request.csrfToken, cookieOptions)
    }

    /**
     * Share with the view engine
     */
    this.shareCsrfViewLocals(ctx)
  }
}

/**
 * A factory function that returns a new function to enforce CSRF
 * protection
 */
export function csrfFactory(
  options: CsrfOptions,
  encryption: Encryption,
  viewProvider?: ViewContract
) {
  if (!options.enabled) {
    return noop
  }

  const csrfMiddleware = new Csrf(options, encryption, viewProvider)
  return csrfMiddleware.handle.bind(csrfMiddleware)
}
