module.exports = {
  /**
   * Returns an object containing request options.  Note that any options you directly set will
   * override the
   *
   * Can be used to pass through custom per user proxy settings like this:
   *
   * ```
   * getRequestOptions: (requestOptions, userOptions) => {
   *    requestOptions.proxy = `https://${options.proxyUsername}:${options.proxyPassword}@myproxy:8080`;
   *    return requestOptions;
   * }
   * ```
   *
   * Note that you would also need to define the `proxyUsername` and `proxyPassword` options as part of the VirusTotal
   * config.
   *
   * @param requestOptions, an objects with the default request options already set
   * @param userOptions, user options for the requesting user
   * @returns {*}
   */
  getRequestOptions: (requestOptions, userOptions) => {
    return requestOptions;
  }
};
