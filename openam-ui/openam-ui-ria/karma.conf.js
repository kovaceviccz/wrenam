/* global module, process */

module.exports = async function (config) {

    process.env.CHROME_BIN = await require("puppeteer").executablePath();

    config.set({
        basePath: ".",
        /*
         * Order matters. Karma prepends each framework's files, so the framework listed
         * last is loaded first. Mocha's UMD bundle registers itself as an anonymous AMD
         * module whenever "define" is already present, which leaves "window.mocha" unset
         * and breaks karma-mocha. Listing Mocha last makes it load before RequireJS.
         */
        frameworks: ["requirejs", "mocha"],
        files: [
            { pattern: "target/test/test-main.js" },
            { pattern: "target/test/**/*.js", included: false },
            { pattern: "target/www/**/*.js", included: false },
            { pattern: "target/ui-compose/libs/**/*.js", included: false },
            { pattern: "node_modules/chai/chai.js", included: false },
            { pattern: "node_modules/sinon-chai/lib/sinon-chai.js", included: false }
        ],
        exclude: [],
        preprocessors: {
            "target/test/**/*.js": ["babel"]
        },
        babelPreprocessor: {
            options: {
                ignore: ["target/test/libs/"],
                presets: [
                    [
                        "@babel/preset-env",
                        { "targets": "last 2 versions, not dead, > 0.2%" }
                    ]
                ]
            }
        },
        reporters: ["mocha"],
        mochaReporter: {
            output: "autowatch"
        },
        port: 9876,
        colors: true,
        logLevel: config.LOG_INFO,
        autoWatch: true,
        browsers: ["ChromeHeadlessNoSandbox"],
        singleRun: true,
        customLaunchers: {
            ChromeHeadlessNoSandbox: {
                base: "ChromeHeadless",
                flags: ["--no-sandbox"]
            }
        }
    });
};
