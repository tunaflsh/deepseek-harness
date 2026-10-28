/**
 * Internal platform-profile builders for the local sandbox provider.
 *
 * @module @deepseek-ai/dsh-sandbox-local/profiles
 */

import { existsSync } from 'node:fs'
import { grantArgs as landlockGrantArgs } from '@deepseek-ai/node-addon-system/landlock-run'
import { workspaceWritableRoots, writableRoots } from '@deepseek-ai/dsh-sandbox'
import type { SandboxPolicy } from '@deepseek-ai/dsh-sandbox'

/** Container and VM daemons that grant unauthenticated host authority on the caller. */
const HOST_DAEMON_SOCKETS = [
  '/var/run/docker.sock',
  '/run/docker.sock',
  '/run/podman/podman.sock',
  '/var/run/podman/podman.sock',
  '/run/containerd/containerd.sock',
  '/run/libvirt/libvirt-sock',
]

/** The per-user runtime directory. */
function runtimeDirectory(env: NodeJS.ProcessEnv): string {
  /* v8 ignore next -- bwrap exists only where process.getuid does */
  return env.XDG_RUNTIME_DIR ?? `/run/user/${process.getuid?.() ?? 0}`
}

/**
 * Agent sockets named by the environment: `SSH_AUTH_SOCK`, and legacy homedir
 * sockets (GnuPG before 2.1.13).
 */
function credentialSockets(env: NodeJS.ProcessEnv): string[] {
  const paths: string[] = []
  const add = (path: string | undefined): void => {
    if (path !== undefined && path.startsWith('/')) paths.push(path)
  }
  add(env.SSH_AUTH_SOCK)
  const gnupg = env.GNUPGHOME
  if (gnupg !== undefined && gnupg.startsWith('/')) {
    for (const name of ['S.gpg-agent', 'S.gpg-agent.extra', 'S.gpg-agent.ssh', 'S.keyboxd', 'S.scdaemon']) add(`${gnupg}/${name}`)
  }
  return paths
}

/** Session-bus sockets: the standard per-user path and any environment override. */
function sessionBusSockets(env: NodeJS.ProcessEnv): string[] {
  const paths: string[] = []
  paths.push(`${runtimeDirectory(env)}/bus`)
  const bus = /(?:^|;)unix:path=([^;,]+)/u.exec(env.DBUS_SESSION_BUS_ADDRESS ?? '')
  if (bus === null) return paths
  /* v8 ignore next -- the capture group matches at least one character, so it cannot be undefined */
  if (bus[1] !== undefined) paths.push(bus[1])
  return paths
}

/**
 * Build the bwrap profile arguments for one file-effect policy and local IPC masking.
 *
 * @param policy - file-effect policy to express as bwrap mounts.
 * @returns profile arguments before the trailing separator and command argv.
 */
export function bwrapProfileArgs(policy: SandboxPolicy): string[] {
  const args = ['--ro-bind', '/', '/', '--dev', '/dev', '--unshare-pid', '--proc', '/proc', '--die-with-parent']
  const gnupg = `${runtimeDirectory(process.env)}/gnupg`
  if (existsSync(gnupg)) args.push('--tmpfs', gnupg, '--remount-ro', gnupg)
  const masked = new Set<string>()
  for (const socket of [...credentialSockets(process.env), ...sessionBusSockets(process.env), ...HOST_DAEMON_SOCKETS]) {
    if (socket.startsWith(`${gnupg}/`)) continue
    if (masked.has(socket) || !existsSync(socket)) continue
    masked.add(socket)
    args.push('--ro-bind', '/dev/null', socket)
  }
  if (policy.mode === 'workspace-write') {
    args.push('--tmpfs', '/tmp')
    for (const root of workspaceWritableRoots(policy)) args.push('--bind', root, root)
  }
  return args
}

/**
 * Build the Landlock launcher grants for one file-effect policy.
 * @param policy - file-effect policy to express as Landlock allow-list grants.
 * @returns launcher grant arguments before the trailing separator and command argv.
 */
export function landlockProfileArgs(policy: SandboxPolicy): string[] {
  const readWrite = ['/dev/null']
  if (policy.mode === 'workspace-write') {
    readWrite.push('/tmp', ...workspaceWritableRoots(policy))
  }
  return landlockGrantArgs({ readOnly: ['/'], readWrite })
}

/** Quote one path as an SBPL string literal. */
function sbplString(path: string): string {
  return `"${path.replaceAll('\\', String.raw`\\`).replaceAll('"', String.raw`\"`)}"`
}

/**
 * Build the sandbox-exec arguments and SBPL profile for one policy. The
 * workspace-owned writable roots (workspace plus explicit extra directories)
 * come from the shared {@link writableRoots} helper (canonical, deduplicated)
 * so the Seatbelt grant and the in-process fs fence
 * (`@deepseek-ai/dsh-fs-sandbox`) can never drift apart; the helper adds the
 * documented Seatbelt temp areas.
 * @param policy - file-effect policy to express as an SBPL profile.
 * @returns sandbox-exec arguments before the trailing separator and command argv.
 */
export function seatbeltProfileArgs(policy: SandboxPolicy): string[] {
  const forms = ['(version 1)', '(allow default)', '(deny file-write*)', `(allow file-write* (literal ${sbplString('/dev/null')}))`]
  const roots = writableRoots(policy)
  if (roots.length > 0) {
    forms.push(`(allow file-write* ${roots.map(root => `(subpath ${sbplString(root)})`).join(' ')})`)
  }
  return ['-p', forms.join(' ')]
}
