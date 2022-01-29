const path = require('path');

module.exports = {
    entry: './src/hscrypt.ts',
    devtool: 'inline-source-map',
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
    },
    output: {
        filename: 'hscrypt.bundle.js',
        path: path.resolve(__dirname, 'dist'),
        libraryTarget: 'umd',
        library: 'hscrypt',
        clean: true,
    },
    // optimization: {
    //     runtimeChunk: 'single',
    // },
};
