import { cleanup, render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it } from "vitest";

import { EncodingPage } from "../src/pages/encoding-page";

afterEach(cleanup);

describe("Encoding workbench page", () => {
  it("decodes base64 input live", async () => {
    render(<EncodingPage />);
    const input = screen.getByLabelText<HTMLTextAreaElement>("Input");
    await userEvent.type(input, "aGVsbG8=");
    const output = screen.getByLabelText<HTMLTextAreaElement>("Output");
    expect(output.value).toBe("hello");
  });

  it("switches codec and direction to encode hex", async () => {
    render(<EncodingPage />);
    await userEvent.click(screen.getByRole("button", { name: "Hex" }));
    await userEvent.click(screen.getByRole("button", { name: "encode" }));
    await userEvent.type(screen.getByLabelText("Input"), "AB");
    const output = screen.getByLabelText<HTMLTextAreaElement>("Output");
    expect(output.value).toBe("4142");
  });

  it("shows a friendly error for malformed input instead of crashing", async () => {
    render(<EncodingPage />);
    await userEvent.type(screen.getByLabelText("Input"), "%zz");
    await userEvent.click(screen.getByRole("button", { name: "URL" }));
    expect(screen.getByRole("alert")).toHaveTextContent(/invalid percent-encoding/i);
  });
});
