import { createInterface } from 'node:readline/promises';
import { stdin as input, stdout as output } from 'node:process';

export interface PromptChoiceOption {
  id: string;
  label: string;
}

export interface PromptChoiceInput {
  title: string;
  options: readonly PromptChoiceOption[];
  defaultOptionId?: string;
}

export async function promptChoice(
  promptInput: PromptChoiceInput,
): Promise<string | null> {
  const lines = [promptInput.title, ''];

  for (const option of promptInput.options) {
    const suffix =
      option.id === promptInput.defaultOptionId ? ' (default)' : '';
    lines.push(`  [${option.id}] ${option.label}${suffix}`);
  }

  lines.push('', 'Enter a choice and press Return.');

  const readline = createInterface({
    input,
    output,
    terminal: true,
  });

  try {
    const answer = (await readline.question(`${lines.join('\n')}\n> `)).trim();

    if (answer.length === 0 && promptInput.defaultOptionId) {
      return promptInput.defaultOptionId;
    }

    const matched = promptInput.options.find((option) => option.id === answer);

    return matched?.id ?? null;
  } finally {
    readline.close();
  }
}
