import { Ruleset } from './types.js';
import { secretsV1Rules } from './secrets_v1.js';
import { containersV1Rules } from './containers_v1.js';
import { aiArtifactsV1Rules } from './ai_artifacts_v1.js';

export const RULESETS: Ruleset[] = [
  { id: 'secrets_v1', rules: secretsV1Rules },
  { id: 'containers_v1', rules: containersV1Rules },
  { id: 'ai_artifacts_v1', rules: aiArtifactsV1Rules },
];

export function getRulesets(ids: string[]): Ruleset[] {
  return RULESETS.filter((set) => ids.includes(set.id));
}
