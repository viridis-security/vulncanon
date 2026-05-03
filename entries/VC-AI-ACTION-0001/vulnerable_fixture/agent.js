'use strict';

// VULNERABLE: irreversible tools execute in the same turn as the prompt.
// No confirmation token, no plan/execute split.

const projects = { 'p-1': { id: 'p-1', deleted: false } };

const TOOLS = {
  delete_project: {
    irreversible: true,
    run: async ({ id }) => {
      if (projects[id]) projects[id].deleted = true;
      return { ok: true, id };
    },
  },
};

async function dispatch(call) {
  const tool = TOOLS[call.name];
  // VULNERABLE: irreversible flag is read but no confirmation gate exists.
  return tool.run(call.args);
}

module.exports = { dispatch, projects };
