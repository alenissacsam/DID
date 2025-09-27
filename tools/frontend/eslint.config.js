import js from "@eslint/js";
import globals from "globals";
import reactRefresh from "eslint-plugin-react-refresh";
import tseslint from "@typescript-eslint/eslint-plugin";
import tsParser from "@typescript-eslint/parser";
import reactPlugin from "eslint-plugin-react";
import reactHooks from "eslint-plugin-react-hooks";
import simpleImportSort from "eslint-plugin-simple-import-sort";
import prettier from "eslint-config-prettier";

export default [
    {
        files: ["**/*.{ts,tsx}"],
        languageOptions: {
            parser: tsParser,
            parserOptions: {
                ecmaFeatures: { jsx: true },
                ecmaVersion: "latest",
                sourceType: "module"
            },
            globals: {
                ...globals.browser
            }
        },
        plugins: {
            "@typescript-eslint": tseslint,
            react: reactPlugin,
            "react-refresh": reactRefresh,
            "react-hooks": reactHooks,
            "simple-import-sort": simpleImportSort
        },
        settings: {
            react: {
                version: "detect"
            }
        },
        rules: {
            ...js.configs.recommended.rules,
            ...tseslint.configs.recommended.rules,
            ...reactPlugin.configs.recommended.rules,
            ...reactHooks.configs.recommended.rules,
            "react/react-in-jsx-scope": "off",
            "react/prop-types": "off",
            "react-refresh/only-export-components": "off",
            "simple-import-sort/imports": "error",
            "simple-import-sort/exports": "error"
        }
    },
    prettier
];
