const path = require('path');

module.exports = {
  mode: 'production',
  entry: './racer/background.js',
  output: {
    filename: 'background.bundle.js',
    path: path.resolve(__dirname, 'racer'),
  },
  optimization: {
    minimize: false, // Keep code readable for debugging if needed, or set to true for minification
  },
};
