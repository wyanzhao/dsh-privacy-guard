import { isAbsolute } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createDictionaryLoader } from './dictionary.js';
import { redactMessages } from './redactor.js';

export const version = '1.3.0';

export function apply(ctx, config = {}) {
  const allowed = new Set(['dictionaryPath', 'blockAttachments']);
  if (Object.keys(config).some((key) => !allowed.has(key)))
    throw new Error('Privacy guard: unknown configuration field.');
  if (config.blockAttachments !== undefined && typeof config.blockAttachments !== 'boolean')
    throw new Error(
      'Privacy guard: legacy blockAttachments must be boolean (it no longer blocks anything).',
    );
  if (
    config.dictionaryPath !== undefined &&
    (typeof config.dictionaryPath !== 'string' || !isAbsolute(config.dictionaryPath))
  )
    throw new Error('Privacy guard: dictionaryPath must be an absolute local path.');
  const dictionaryPath =
    config.dictionaryPath ?? fileURLToPath(new URL('./private-terms.json', import.meta.url));
  const load = createDictionaryLoader(dictionaryPath, {
    optional: config.dictionaryPath === undefined,
  });
  load();
  ctx.on('agent/pre-step', async (_payload, next) => {
    const decision = await next();
    if (decision.kind !== 'enter') return decision;
    return { ...decision, messages: redactMessages(decision.messages, load().redact) };
  });
  // No llm/stream denial or request mutation: newly admitted text is already masked.
  ctx.inject(['commands'], (commandCtx) => {
    commandCtx.effect(() =>
      commandCtx.commands.register({
        name: 'privacy',
        description: '本地隐私替换状态与预览：敏感文本替换为 *，不阻断请求',
        input: { hint: 'status | preview <text>' },
        recordInput: false,
        handler: ({ rawInput }) => {
          const state = load();
          const warning = state.warning ? `\n注意：${state.warning}` : '';
          const dictionary = state.configured
            ? '已加载个人词库。'
            : '未配置个人词库，仅使用内置规则。';
          const input = rawInput.trim();
          if (!input || input === 'status')
            return {
              kind: 'success',
              text: `隐私替换 ${version} 已启用：新 prompt 命中的敏感信息统一替换为一个 *，继续发送，不阻断。图片与文件原样放行、未脱敏；已有历史与工具输出不追溯改写。姓名和地址仅识别标签字段或自定义词条，不保证零漏检。${dictionary}${warning}`,
            };
          if (input.startsWith('preview ')) {
            const result = state.redact(input.slice(8));
            return {
              kind: 'success',
              text: `本地替换预览（未发送模型）：\n${result.text}\n命中统计：${JSON.stringify(result.counts)}${warning}`,
            };
          }
          return {
            kind: 'error',
            text: '用法：/privacy status 或 /privacy preview <文本>。此命令不调用模型。',
          };
        },
      }),
    );
  });
}
