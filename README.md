# httpstat

MyPaste extension `com.mypaste.httpstat` (version `1.0.1`).

打开一条链接就测量它的 HTTP 时序：DNS 解析、TCP 连接、TLS 握手、等待响应与内容传输分段计时，用瀑布图与表格对照，并列出状态码、协议、远端地址与响应头；地址可以改，随时重新计时，也能复制完整报告。计时由包内 Go 程序针对这一条地址发出一次 GET，不读取其它条目，也不把地址或结果写到别处。新的报告会自己画出来：每段色条按各自的时长长到位，累计刻度在色条到达它的边界时落下；改变窗口大小只重画、不重播，系统偏好减少动态效果时整段跳过。

This repository is an independent copy extracted from the former `mypaste-code-extensions` monorepo at commit `dde7b6bb20a070ddf0908034e8a873f087ff77c0`. It contains only this extension's tracked source files. The published `.mypaste-plugin` archives and marketplace index live in [`mypaste-extensions-catalog`](https://github.com/mypaste/mypaste-extensions-catalog).

The manifest speaks MyPaste plugin protocol v3. Installation, capability mediation, and content-digest verification are performed by the MyPaste desktop host.

## Files

- `mypaste.plugin.json`: package identity, the `entity.read` and
  `clipboard.write` capabilities, and the internal `probe` command the surface
  invokes.
- `src/preview.html`, `src/main.ts`, `src/bridge.ts`, `src/report.ts`: the
  surface page, its bridge to the host, and the pure report module.
- `src/cmd/mypaste-httpstat`, `src/internal/probe`: the Go runtime that makes
  the measured request and reports the timings.
- `scripts/build.mjs`: bundles `src/preview.html` and `src/main.ts` into the
  page the manifest names.

## Build

```bash
bun install
bun run build
```

The generated `preview.html` is intentionally ignored; edit `src/preview.html`
and `src/main.ts` instead. The `httpstat` runtime is built from
`src/cmd/mypaste-httpstat` with Go 1.27.1 and ships as the archive's
`httpstat` entrypoint.

## License

MIT. See [LICENSE](LICENSE).
