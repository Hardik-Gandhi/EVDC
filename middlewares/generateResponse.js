module.exports = (req, res, next) => {
    res.sendJson = (response) => {
      if (!(typeof response == "object" && response.message && response.data)){
        response = (typeof response == "string") ? { message : response }: {data: response};
      }
      response.status = true;
      if (!(res.statusCode >= 200 && res.statusCode < 300)) {
        response.status = false;
      }
      return res.json(response);
    };
    next();
};