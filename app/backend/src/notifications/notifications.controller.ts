@Get("in-app")
getInApp(
  @Req() req,
  @Query("page") page = 1,
  @Query("limit") limit = 20,
) {
  return this.inAppRepo.findByUser(req.user.publicKey, page, limit);
}

@Post("in-app/:id/read")
markRead(@Param("id") id: string) {
  return this.inAppRepo.markAsRead(id);
}

@Post("in-app/read-all")
markAll(@Req() req) {
  return this.inAppRepo.markAllAsRead(req.user.publicKey);
}