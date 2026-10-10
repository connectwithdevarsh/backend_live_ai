// Unit test for Phase 4 Backend Proxy tool validation & schema logic
const assert = require('assert');

// 1. Tool Definitions and Allowlist
const REGISTERED_TOOLS = [
  'launch_app',
  'open_setting',
  'toggle_flashlight',
  'adjust_volume',
  'set_volume',
  'set_alarm',
  'set_timer',
];

function validateToolCalls(plan) {
  if (!Array.isArray(plan)) return [];
  return plan.map((step, idx) => {
    const tool = step.tool ? String(step.tool).trim().toLowerCase() : '';
    const isRegistered = REGISTERED_TOOLS.includes(tool);
    return {
      step: typeof step.step === 'number' ? step.step : idx + 1,
      description: step.description || `Step ${idx + 1}`,
      tool: isRegistered ? tool : 'unknown',
      arguments: typeof step.arguments === 'object' && step.arguments !== null ? step.arguments : {},
      risk: ['low', 'moderate', 'sensitive'].includes(step.risk) ? step.risk : 'low',
      isAuthorized: isRegistered,
    };
  });
}

function testToolValidation() {
  console.log('Testing Backend Tool Validation Allowlist...');

  const validPlan = [
    { step: 1, description: 'Open Settings', tool: 'open_setting', arguments: { settingType: 'settings' }, risk: 'low' },
    { step: 2, description: 'Open Bluetooth', tool: 'open_setting', arguments: { settingType: 'bluetooth' }, risk: 'low' },
  ];

  const validatedValid = validateToolCalls(validPlan);
  assert.strictEqual(validatedValid.length, 2);
  assert.strictEqual(validatedValid[0].isAuthorized, true);
  assert.strictEqual(validatedValid[1].isAuthorized, true);
  console.log('  ✓ Valid registered tools approved.');

  const maliciousPlan = [
    { step: 1, description: 'Execute Shell', tool: 'run_shell_command', arguments: { cmd: 'rm -rf /' }, risk: 'sensitive' },
    { step: 2, description: 'Turn on Flashlight', tool: 'toggle_flashlight', arguments: { enable: true }, risk: 'moderate' },
  ];

  const validatedMalicious = validateToolCalls(maliciousPlan);
  assert.strictEqual(validatedMalicious[0].isAuthorized, false);
  assert.strictEqual(validatedMalicious[0].tool, 'unknown');
  assert.strictEqual(validatedMalicious[1].isAuthorized, true);
  assert.strictEqual(validatedMalicious[1].tool, 'toggle_flashlight');
  console.log('  ✓ Malicious / unauthorized tools rejected to "unknown".');

  console.log('Backend Tool Validation Tests Passed Successfully!\n');
}

testToolValidation();
