import { describe, expect, it } from "vitest";
import { nestedRecord, nestedString, recordValue, type JsonRecord } from "../src/nativeParserUtils.js";

describe("native parser object path helpers", () => {
  it("reads own nested string and record values", () => {
    const record = {
      metadata: {
        owner: "security",
      },
    } as JsonRecord;

    expect(nestedString(record, ["metadata", "owner"])).toBe("security");
    expect(recordValue(record, "metadata")).toEqual({ owner: "security" });
    expect(nestedRecord(record, ["metadata"])).toEqual({ owner: "security" });
  });

  it("does not traverse inherited record values", () => {
    const record = Object.create({ inherited: { owner: "prototype" } }) as JsonRecord;
    record.metadata = { owner: "security" };

    expect(nestedString(record, ["metadata", "owner"])).toBe("security");
    expect(nestedString(record, ["inherited", "owner"])).toBeNull();
    expect(recordValue(record, "inherited")).toBeNull();
  });

  it("blocks prototype-sensitive path segments even when present as own JSON keys", () => {
    const record = JSON.parse(
      '{"__proto__":{"owner":"blocked"},"constructor":{"owner":"blocked"},"prototype":{"owner":"blocked"},"metadata":{"owner":"security"}}',
    ) as JsonRecord;

    expect(nestedString(record, ["metadata", "owner"])).toBe("security");
    expect(nestedRecord(record, ["__proto__"])).toBeNull();
    expect(nestedRecord(record, ["constructor"])).toBeNull();
    expect(nestedRecord(record, ["prototype"])).toBeNull();
  });
});
