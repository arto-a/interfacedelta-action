import * as core from '@actions/core';
import { runAction } from './action';

await runAction({
  getInput: (name) => core.getInput(name),
  setOutput: (name, value) => core.setOutput(name, value),
  warning: (message) => core.warning(message),
  error: (message) => core.error(message),
  setFailed: (message) => core.setFailed(message),
  setSecret: (value) => core.setSecret(value),
  writeSummary: async (markdown) => {
    await core.summary.addRaw(markdown).write();
  },
});
