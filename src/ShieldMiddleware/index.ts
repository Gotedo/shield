/*
* @adonisjs/shield
*
* (c) Harminder Virk <virk@adonisjs.com>
*
* For the full copyright and license information, please view the LICENSE
* file that was distributed with this source code.
*/

import { ShieldConfig } from '@ioc:Adonis/Addons/Shield'
import { HttpContextContract } from '@ioc:Adonis/Core/HttpContext'

import * as shield from '../../standalone'

/**
 * Shield middleware to protect web applications against common
 * web attacks
 */
export class ShieldMiddleware {
  /**
   * Actions to be performed
   */
  private actions = [
    shield.csrfFactory(this.config.csrf || {}, this.appKey),
    shield.cspFactory(this.config.csp || {}),
    shield.dnsPrefetchFactory(this.config.dnsPrefetch || {}),
    shield.frameGuardFactory(this.config.xFrame || {}),
    shield.hstsFactory(this.config.hsts || {}),
    shield.noOpenFactory(this.config.noOpen || {}),
    shield.noSniffFactory(this.config.contentTypeSniffing || {}),
    shield.xssFactory(this.config.xss || {}),
  ]

  constructor (private config: ShieldConfig, private appKey: string) {
  }

  /**
   * Handle request
   */
  public async handle (ctx: HttpContextContract, next: () => Promise<void>) {
    for (let action of this.actions) {
      await action(ctx)
    }

    await next()
  }
}
