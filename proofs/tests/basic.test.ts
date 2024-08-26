import { circomkit, WitnessTester, generateDescription } from "./common";

describe("ASCII", () => {
    let circuit: WitnessTester<["in"], ["out"]>;

    function generatePassCase(input: any, expected: any, desc: string) {
        const description = generateDescription(input);

        it(`(valid) witness: ${description}\n${desc}`, async () => {
            await circuit.expectPass(input, expected);
        });
    }
    before(async () => {
        circuit = await circomkit.WitnessTester(`ASCII`, {
            file: "circuits/proof",
            template: "Proof",
        });
        console.log("#constraints:", await circuit.getConstraintCount());
    });

    generatePassCase({ in: [1, 2, 3, 4, 5] }, { out: 1 }, "A basic test...");
});