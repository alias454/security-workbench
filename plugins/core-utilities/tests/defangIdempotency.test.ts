import { describe, expect, it } from "vitest";
import { defangIocsSkill } from "../src/defangIocs.js";

describe("defang_iocs idempotency", () => {
  it("does not double-defang already defanged dots or at signs", () => {
    const result = defangIocsSkill.run(
      "hxxps://already[.]defanged[.]example admin[@]example[.]com"
    );

    expect(result).toEqual({
      defanged: "hxxps://already[.]defanged[.]example admin[@]example[.]com",
    });
  });

  it("defangs raw characters while preserving already defanged tokens", () => {
    const result = defangIocsSkill.run(
      "https://evil.example.com admin@example.com hxxps://already[.]defanged[.]example"
    );

    expect(result).toEqual({
      defanged:
        "hxxps://evil[.]example[.]com admin[@]example[.]com hxxps://already[.]defanged[.]example",
    });
  });

  it("preserves alternate existing defanged token forms", () => {
    const result = defangIocsSkill.run(
      "evil(dot)example[dot]com admin(at)example(.)com"
    );

    expect(result).toEqual({
      defanged: "evil(dot)example[dot]com admin(at)example(.)com",
    });
  });
});
