/**
 * A minimal external plugin used by tests: it suggests one custom profile,
 * `fieldtech`, so the CLI's plugin-profile resolution can be exercised end to end.
 */
export default {
  name: "fieldkit",
  profiles: {
    fieldtech: { name: "fieldtech", allows: ["hail", "directory"], description: "a field technician's kit" },
  },
  routes: [],
};
