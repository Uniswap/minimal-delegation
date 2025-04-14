const { build } = require("esbuild");

const entryPoints = ["sign-typed-data", "sign-wrapped-typed-data"];

const sharedConfig = {
    bundle: true,
    minify: false,
};

for (const entryPoint of entryPoints) {
    build({
        entryPoints: [`src/${entryPoint}.ts`],
        ...sharedConfig,
        platform: "node",
        outfile: `dist/${entryPoint}.js`,
    });
}