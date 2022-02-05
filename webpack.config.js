var path = require('path');

module.exports = {
    entry: './src/hscrypt.ts',
    module: {
        rules: [
            {
                test: /\.ts$/,
                use: 'ts-loader',
                exclude: /node_modules/,
            },
        ],
    },
    resolve: {
        extensions: [ '.ts', '.js', ],
        fallback: {
            crypto: require.resolve("crypto-browserify"),
        },
    },
    output: {
        path: path.resolve(__dirname, 'dist'),
        filename: 'hscrypt.js',
        library: 'hscrypt'
    },
};
