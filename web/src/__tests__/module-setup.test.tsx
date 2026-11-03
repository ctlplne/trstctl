import { useState } from "react";
import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ModuleSetupFields } from "@/pages/connectors/ModuleSetupFields";

function Editor() {
  const [config, setConfig] = useState('{"endpoint":"https://lb.internal"}');
  return (
    <>
      <ModuleSetupFields
        inputs={[
          { name: "partition", type: "string", required: true, secret: false, description: "the appliance partition" },
          { name: "admin_ref", type: "string", required: false, secret: true },
          { name: "port", type: "integer", required: false, secret: false },
          { name: "strict", type: "boolean", required: false, secret: false },
        ]}
        config={config}
        onChange={setConfig}
      />
      <output data-testid="config">{config}</output>
    </>
  );
}

describe("connector module setup (A242)", () => {
  it("edits the destination configuration from the module's declared inputs", async () => {
    const user = userEvent.setup();
    render(<Editor />);
    await user.type(screen.getByRole("textbox", { name: /partition/ }), "edge");
    await user.type(screen.getByRole("textbox", { name: /admin_ref/ }), "secret://lb-admin");
    await user.type(screen.getByRole("spinbutton", { name: /port/ }), "8443");
    await user.click(screen.getByRole("checkbox", { name: /strict/ }));
    expect(JSON.parse(screen.getByTestId("config").textContent ?? "")).toEqual({
      endpoint: "https://lb.internal",
      partition: "edge",
      admin_ref: "secret://lb-admin",
      port: 8443,
      strict: true,
    });
    expect(screen.getByRole("textbox", { name: /admin_ref/ })).toHaveAttribute("placeholder", "secret://name");
    expect(screen.getByText(/never the value itself/)).toBeInTheDocument();
  });
});
