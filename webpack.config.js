var path = require('path');

// const ENV = process.env['NODE_ENV']
// const production = ENV === 'production'

module.exports = {
    // mode: 'production',
    entry: './src/hscrypt.ts',
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: 'hscrypt.js',
        library: 'hscrypt'
    },
    module: {
        rules: [
            {
                test: /\.ts$/,
                use: 'ts-loader',
                exclude: /node_modules/,
            },
        ],
    },
    "resolve": {
        "fallback": {
            "crypto": require.resolve("crypto-browserify"),
        },
    },
    resolve: {
        extensions: [ '.ts', '.js', ],
    },
    // externals: {
    //     lodash: {
    //         commonjs: 'lodash',
    //         commonjs2: 'lodash',
    //         amd: 'lodash',
    //         root: '_'
    //     }
    // }
};
