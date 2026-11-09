import React from "react";

export function CommentBox({ userComment, element }) {
  element.innerHTML = userComment;
  return <div dangerouslySetInnerHTML={{ __html: userComment }} />;
}

export function SafeCommentBox({ userComment, element }) {
  element.textContent = userComment;
  return <div>{userComment}</div>;
}
